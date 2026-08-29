"""Reassemble a TCP byte stream into whole application messages.

The counterpart to :mod:`packeteer.parse.defragment`, one layer up.  That
module puts IP fragments back into datagrams; this one puts TCP segments back
into the messages a length-prefixed protocol sends, so that a message split
across three segments decodes as one message rather than three broken ones.

It is driven by a callable the protocol supplies —
:attr:`~packeteer.protocols.AppProtocol.frame_length`, which is handed the
bytes of a flow so far and returns how long the message at the front is, or
``None`` when there is not yet enough to tell.  That is the whole interface: a
reassembler that had to understand the protocol would be a second decoder.

**Bytes are placed by sequence number, not arrival order.**  A retransmission
is dropped, an overlap contributes only its new part, and a gap is held rather
than spliced over.  This is not fastidiousness: ``packeteer stream`` with
:class:`~packeteer.generate.impairments.ImpairmentOptions` emits spurious
retransmissions and leaves permanent gaps where a segment was lost, so a
reader that trusted arrival order would mis-decode packeteer's own output —
the first corpus anyone would test a new spec against.

Everything is bounded.  A reassembler without caps is a memory-exhaustion bug
waiting for a crafted capture, so a flow that grows too large, waits too long,
or arrives among too many others is abandoned and reported rather than kept.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from packeteer.generate.ip import IPHeader
from packeteer.generate.tcp import TCPHeader

if TYPE_CHECKING:
    from packeteer.parse.core import ParsedPacket

__all__ = [
    "FlowKey",
    "IncompleteMessage",
    "ReassembledMessage",
    "Reassembler",
]

_SYN = 0x02
_SEQ_SPACE = 1 << 32


@dataclass(frozen=True)
class FlowKey:
    """One direction of one TCP connection.

    Attributes:
        src: Source address, as it appeared in the header.
        dst: Destination address.
        src_port: Source port.
        dst_port: Destination port.

    """

    src: str
    dst: str
    src_port: int
    dst_port: int


@dataclass
class ReassembledMessage:
    """One whole application message, and what carried it.

    Attributes:
        data: The message bytes, exactly as the sender framed them.
        flow: Which direction of which connection it came from.
        tokens: Tokens of the packets that contributed, in arrival order.

    """

    data: bytes
    flow: FlowKey
    tokens: list[Any] = field(default_factory=list)


@dataclass
class IncompleteMessage:
    """A message that never completed, and why.

    Attributes:
        flow: Which direction of which connection it was on.
        bytes_seen: Payload bytes collected before it was abandoned.
        expected_bytes: How long the message was going to be, when the prefix
            said so before it was abandoned; ``None`` when even that was not
            known.
        reason: ``"timeout"``, ``"gap"``, ``"too_large"``, ``"too_many_flows"``
            or ``"eof"``.
        tokens: Tokens of the packets that did arrive, in arrival order.

    """

    flow: FlowKey
    bytes_seen: int
    expected_bytes: int | None
    reason: str
    tokens: list[Any] = field(default_factory=list)


@dataclass
class _Flow:
    """The bytes collected for one direction of one connection."""

    #: Sequence number of ``buffer[0]``.
    base: int = 0
    started: bool = False
    buffer: bytearray = field(default_factory=bytearray)
    #: Segments held because the bytes before them have not arrived.
    pending: dict[int, bytes] = field(default_factory=dict)
    tokens: list[Any] = field(default_factory=list)
    bytes_seen: int = 0
    last_seen: float = 0.0
    #: Bytes already handed out as messages.  Once this is non-zero the base
    #: cannot move back, because those bytes are gone.
    delivered: int = 0

    def held(self) -> int:
        """Return how many bytes this flow is holding."""
        return len(self.buffer) + sum(len(v) for v in self.pending.values())


class Reassembler:
    """Collects TCP segments and yields whole messages.

    .. code-block:: python

        engine = Reassembler(frame_length=proto.frame_length)
        for record in capture:
            for message in engine.feed(parse_packet(record.data), token=record):
                proto.decode(message.data, "tcp")
        engine.flush()
        for lost in engine.incomplete:
            ...

    Attributes:
        incomplete: Messages abandoned so far, as
            :class:`IncompleteMessage`.  Only complete once :meth:`flush` has
            run, the same contract
            :attr:`packeteer.parse.defragment.Defragmenter.incomplete` has.

    """

    def __init__(
        self,
        frame_length: Callable[[bytes], int | None],
        *,
        timeout_s: float = 30.0,
        max_message_bytes: int = 1 << 20,
        max_flows: int = 1024,
    ) -> None:
        """Set the reassembler up.

        Args:
            frame_length: Given a flow's bytes so far, returns the total
                length of the message at the front, or ``None`` when there is
                not yet enough to tell.
            timeout_s: Seconds of *capture* time to wait for a flow's missing
                bytes before abandoning it.
            max_message_bytes: Cap on the bytes held for one flow.  A message
                larger than this is abandoned rather than buffered.
            max_flows: Cap on how many flows are tracked at once.  The oldest
                is abandoned when a new one would exceed it.

        """
        self._frame_length = frame_length
        self._timeout_s = timeout_s
        self._max_message_bytes = max_message_bytes
        self._max_flows = max_flows
        self._flows: dict[FlowKey, _Flow] = {}
        self.incomplete: list[IncompleteMessage] = []

    def feed(self, pkt: "ParsedPacket", token: Any = None) -> list[ReassembledMessage]:
        """Feed one packet and return the messages it completes.

        A packet that is not TCP over IP, or that carries no payload, is
        ignored, except that a SYN establishes where the flow's data starts.

        **A FIN is not treated as the end of a flow.**  A capture routinely
        carries retransmissions after the FIN that closes a connection, and
        some of them fill a gap left by a segment that was lost.  Forgetting
        the flow at the FIN would both discard those bytes and take the next
        retransmission for the start of a new conversation, handing out a
        message twice.  Flows end by timing out, or at :meth:`flush`.

        Args:
            pkt: A parsed packet.
            token: Anything identifying this packet — a
                :class:`~packeteer.pcap.PcapRecord`, a packet number, an
                offset.  It is returned on the messages this packet
                contributes to, and never inspected.

        Returns:
            Every message completed by this packet, in order.

        """
        header = pkt.transport
        if not isinstance(header, TCPHeader) or not isinstance(pkt.ip, IPHeader):
            return []
        when = pkt.ts_sec + (pkt.ts_frac / pkt.tick_hz if pkt.tick_hz else 0.0)
        self._expire(when)

        key = FlowKey(pkt.ip.src, pkt.ip.dst, header.src_port, header.dst_port)
        flow = self._flows.get(key)
        if flow is None:
            if len(self._flows) >= self._max_flows:
                self._abandon_oldest()
            flow = self._flows.setdefault(key, _Flow())
        flow.last_seen = when

        seq = header.seq
        if header.flags & _SYN:
            # A SYN consumes one sequence number, so data starts after it.
            flow.base = (seq + 1) % _SEQ_SPACE
            flow.started = True
            flow.buffer.clear()
            flow.pending.clear()
            return []

        payload = pkt.payload
        if payload:
            if not flow.started:
                # No SYN in the capture, so the first data byte seen defines
                # where this flow starts.
                flow.base = seq
                flow.started = True
            flow.tokens.append(token)
            flow.bytes_seen += len(payload)
            self._place(flow, seq, bytes(payload))
            if flow.held() > self._max_message_bytes:
                self._abandon(key, "too_large")
                return []

        return self._drain(key, flow)

    def flush(self) -> None:
        """Abandon every flow still holding bytes, reporting each.

        Call once the capture is exhausted, so that
        :attr:`incomplete` is complete.
        """
        for key in list(self._flows):
            if self._flows[key].held():
                self._abandon(key, "eof")
            else:
                del self._flows[key]

    # ── placing bytes ─────────────────────────────────────────────────────────

    def _place(self, flow: _Flow, seq: int, payload: bytes) -> None:
        """Put *payload* where its sequence number says it belongs."""
        offset = self._offset(flow.base, seq)
        if offset < 0 and flow.delivered == 0:
            # Earlier than anything seen so far, and nothing has been handed
            # out yet — so this flow started here rather than where the first
            # segment to *arrive* happened to start.  Without this, a capture
            # whose first segment is out of order loses everything before it.
            self._rebase(flow, seq)
            offset = self._offset(flow.base, seq)
        end = len(flow.buffer)
        if offset < 0:
            # Starts before the buffer: a retransmission of bytes already
            # handed out.  Keep only whatever runs past what is held.
            payload = payload[-offset:] if -offset < len(payload) else b""
            offset = 0
        if not payload:
            return
        if offset > end:
            flow.pending[seq] = payload
            return
        overlap = end - offset
        if overlap >= len(payload):
            return                      # entirely a retransmission
        flow.buffer += payload[overlap:]
        self._drain_pending(flow)

    def _rebase(self, flow: _Flow, seq: int) -> None:
        """Move a flow's start back to *seq*, holding what it already had."""
        if flow.buffer:
            flow.pending[flow.base] = bytes(flow.buffer)
            flow.buffer.clear()
        flow.base = seq

    def _drain_pending(self, flow: _Flow) -> None:
        """Move held segments into the buffer once the gap before them fills."""
        moved = True
        while moved:
            moved = False
            for seq in sorted(flow.pending):
                offset = self._offset(flow.base, seq)
                if offset > len(flow.buffer):
                    continue
                payload = flow.pending.pop(seq)
                overlap = len(flow.buffer) - offset
                if overlap < len(payload):
                    flow.buffer += payload[overlap:]
                moved = True
                break

    @staticmethod
    def _offset(base: int, seq: int) -> int:
        """Return *seq*'s distance from *base*, across the 32-bit wrap."""
        delta = (seq - base) % _SEQ_SPACE
        # More than half the space away is a sequence number behind the base,
        # which is how TCP's comparisons work.
        return delta - _SEQ_SPACE if delta > _SEQ_SPACE // 2 else delta

    # ── taking messages out ───────────────────────────────────────────────────

    def _drain(self, key: FlowKey, flow: _Flow) -> list[ReassembledMessage]:
        """Return every whole message now at the front of *flow*."""
        messages: list[ReassembledMessage] = []
        while flow.buffer:
            total = self._frame_length(bytes(flow.buffer))
            if total is None or total <= 0 or len(flow.buffer) < total:
                break
            messages.append(ReassembledMessage(
                data=bytes(flow.buffer[:total]),
                flow=key,
                tokens=list(flow.tokens),
            ))
            del flow.buffer[:total]
            flow.base = (flow.base + total) % _SEQ_SPACE
            flow.delivered += total
            flow.tokens = []
            self._drain_pending(flow)
        return messages

    # ── bounds ────────────────────────────────────────────────────────────────

    def _expire(self, now: float) -> None:
        """Abandon flows that have waited too long for their missing bytes."""
        if not self._timeout_s:
            return
        for key, flow in list(self._flows.items()):
            if flow.last_seen and now - flow.last_seen > self._timeout_s:
                if flow.held():
                    self._abandon(key, "timeout")
                else:
                    del self._flows[key]

    def _abandon_oldest(self) -> None:
        """Make room by abandoning the flow that has waited longest."""
        oldest = min(self._flows, key=lambda k: self._flows[k].last_seen)
        self._abandon(oldest, "too_many_flows")

    def _abandon(self, key: FlowKey, reason: str) -> None:
        """Drop a flow and record what was lost with it."""
        flow = self._flows.pop(key, None)
        if flow is None:
            return
        expected = self._frame_length(bytes(flow.buffer)) if flow.buffer else None
        # Bytes held out of order mean something before them never arrived,
        # which is what actually stalled the flow — more useful than saying
        # the capture ended or the clock ran out.
        if flow.pending and reason in ("timeout", "eof"):
            reason = "gap"
        self.incomplete.append(IncompleteMessage(
            flow=key,
            bytes_seen=flow.bytes_seen,
            expected_bytes=expected,
            reason=reason,
            tokens=list(flow.tokens),
        ))
