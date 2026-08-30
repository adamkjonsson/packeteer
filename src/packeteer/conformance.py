r"""Check an application protocol against the contract every one must meet.

packeteer has two ways to produce an :class:`~packeteer.protocols.AppProtocol`
— written by hand, or compiled from a spec with :mod:`packeteer.protospec` —
and keeps both, because DNS, DHCP and HTTP are not expressible in the spec
subset.  Two mechanisms with no shared test is how they drift, so this module
is the shared test: it takes *any* registered protocol and asserts the same
properties of it.

It is not only for packeteer's own suite.  A protocol you register is treated
exactly like a built-in, so it is worth holding to the same contract::

    from packeteer import conformance, protocols

    failures = conformance.check_protocol(
        protocols.for_section("sensor"),
        [Reading(version=1, samples=[(2, 21)])],
    )
    assert not failures, "\\n".join(failures)

Each check returns *why* it failed rather than raising, so one run reports
everything wrong rather than the first thing.
"""
from __future__ import annotations

import json
import struct
from collections.abc import Sequence

from packeteer import protocols
from packeteer.protocols import AppProtocol

__all__ = ["check_protocol", "canonicalises"]

#: What a codec raises when it rejects bytes or a message of the wrong shape.
#: Named rather than caught blind: these are the failures a protocol *has*,
#: and anything else escaping is a bug in it worth seeing as a traceback.
#: `struct.error` is what a hand-written codec unpacking too few bytes gives,
#: and `AttributeError` what a generated one gives for a field of the wrong
#: type.
_CODEC_ERRORS = (
    ValueError, TypeError, KeyError, IndexError, AttributeError,
    OverflowError, UnicodeDecodeError, struct.error,
)


def _transport_for(proto: AppProtocol) -> str:
    """Return the transport to test *proto* over."""
    return "udp" if proto.over == "either" else proto.over


def canonicalises(proto: AppProtocol, message: object,
                  transport: str | None = None) -> bool:
    """Return whether decoding *message*'s own encoding changes it.

    Not a fault.  A decoder may legitimately normalise — DNS returns
    ``"example.com."`` for a name written ``"example.com"``, because that is
    what the wire format means — and :func:`check_protocol` allows it so long
    as the normalisation is *stable*, which is the property that matters:
    encoding the normalised message again must give the same bytes, or
    something was lost.

    Args:
        proto: The protocol to ask.
        message: A message it can encode.
        transport: ``"tcp"`` or ``"udp"``; the protocol's own when ``None``.

    Returns:
        ``True`` when ``decode(encode(m))`` differs from *m*.

    """
    t = transport or _transport_for(proto)
    return proto.decode(proto.encode(message, t), t) != message


def check_protocol(
    proto: AppProtocol,
    messages: Sequence[object],
    *,
    transport: str | None = None,
) -> list[str]:
    """Return every way *proto* fails the ``AppProtocol`` contract.

    An empty list means it conforms.  Each entry names the property and the
    message that broke it, so a failing run says what to go and fix.

    The properties, and why each is here:

    - **Encoding is stable.** ``encode(decode(encode(m))) == encode(m)``.  A
      decoder may canonicalise (see :func:`canonicalises`), but it may not
      lose anything, and this is the check that tells those apart.
    - **Decoding is exact after that.** ``decode(encode(m1)) == m1`` for the
      canonicalised *m1*.
    - **A spec round trip is lossless.** ``from_spec(to_spec(m)) == m``.
    - **A section is JSON.**  A packet spec is written to a file.
    - **Truncated input raises.**  At *every* byte offset: a decoder that
      returns a half-built object from a short read turns a snaplen-truncated
      capture into a spec that quietly says the missing fields were absent.
    - **The registry resolves it.**  By message type and by every declared
      port on its transport.
    - **Sanitising leaves a section usable.**  Still JSON, and no new keys —
      a redactor is not a place to invent structure.
    - **A whole packet round-trips.**  Built with
      :meth:`~packeteer.generate.builder.PacketBuilder.app`, parsed back, put
      through the spec, and rebuilt: byte for byte.  This is the guarantee
      packeteer exists for, and it was asserted for the two mechanisms
      separately, in different files, with different fixtures.

    Args:
        proto: The protocol to check.
        messages: Representative messages it can encode.  At least one is
            required — a contract cannot be checked against nothing.
        transport: ``"tcp"`` or ``"udp"``.  Defaults to the protocol's own,
            and to ``"udp"`` for one declaring ``"either"``.

    Returns:
        Human-readable failures, empty when *proto* conforms.

    Raises:
        ValueError: If *messages* is empty.

    """
    if not messages:
        raise ValueError(
            f"no sample messages for {proto.name!r}: the contract cannot be "
            f"checked against nothing"
        )
    t = transport or _transport_for(proto)
    failures: list[str] = []

    def fail(prop: str, detail: str, index: int) -> None:
        failures.append(f"{proto.name}: {prop} (message {index}): {detail}")

    for index, message in enumerate(messages):
        try:
            encoded = proto.encode(message, t)
        except _CODEC_ERRORS as exc:
            fail("encode", f"{type(exc).__name__}: {exc}", index)
            continue
        try:
            decoded = proto.decode(encoded, t)
        except _CODEC_ERRORS as exc:
            fail("decode of its own encoding", f"{type(exc).__name__}: {exc}",
                 index)
            continue

        if proto.encode(decoded, t) != encoded:
            fail("encoding is not stable",
                 "encode(decode(encode(m))) differs from encode(m), so "
                 "decoding lost something", index)
        if proto.decode(proto.encode(decoded, t), t) != decoded:
            fail("decoding is not exact", "decode(encode(m1)) != m1", index)

        failures += _check_spec(proto, decoded, index)
        failures += _check_truncation(proto, encoded, t, index)
        failures += _check_sanitise(proto, decoded, index)
        failures += _check_packet_round_trip(proto, decoded, t, index)

    failures += _check_registry(proto, messages, t)
    return failures


def _check_spec(proto: AppProtocol, message: object, index: int) -> list[str]:
    """Check the spec round trip and that a section survives JSON."""
    out: list[str] = []
    try:
        section = proto.to_spec(message)
    except _CODEC_ERRORS as exc:
        return [f"{proto.name}: to_spec (message {index}): "
                f"{type(exc).__name__}: {exc}"]
    try:
        json.dumps(section)
    except (TypeError, ValueError) as exc:
        out.append(f"{proto.name}: a section is not JSON (message {index}): "
                   f"{exc}")
    try:
        if proto.from_spec(section) != message:
            out.append(f"{proto.name}: from_spec(to_spec(m)) != m "
                       f"(message {index})")
    except _CODEC_ERRORS as exc:
        out.append(f"{proto.name}: from_spec (message {index}): "
                   f"{type(exc).__name__}: {exc}")
    return out


def _check_truncation(
    proto: AppProtocol, encoded: bytes, transport: str, index: int,
) -> list[str]:
    """Check that no short prefix of a valid message decodes."""
    accepted = []
    for cut in range(len(encoded)):
        try:
            proto.decode(encoded[:cut], transport)
        except _CODEC_ERRORS:
            continue
        accepted.append(cut)
    if not accepted:
        return []
    shown = ", ".join(str(c) for c in accepted[:8])
    more = "" if len(accepted) <= 8 else f" (and {len(accepted) - 8} more)"
    return [
        f"{proto.name}: truncated input decoded (message {index}): "
        f"{len(accepted)} of {len(encoded)} prefixes were accepted rather "
        f"than raising, at offsets {shown}{more}.  A half-built object from a "
        f"short read makes a snaplen-truncated capture parse into a spec that "
        f"says the missing fields were absent."
    ]


def _check_sanitise(proto: AppProtocol, message: object, index: int) -> list[str]:
    """Check that redaction leaves a section usable."""
    if proto.sanitise is None:
        return []
    from packeteer.sanitise import SanitiseOptions, _Replacer

    section = proto.to_spec(message)
    before = set(section)
    try:
        proto.sanitise(section, _Replacer(), SanitiseOptions())
    except _CODEC_ERRORS as exc:
        return [f"{proto.name}: sanitise (message {index}): "
                f"{type(exc).__name__}: {exc}"]
    out: list[str] = []
    added = set(section) - before
    if added:
        out.append(f"{proto.name}: sanitise added keys {sorted(added)} "
                   f"(message {index}); a redactor is not a place to invent "
                   f"structure")
    try:
        json.dumps(section)
    except (TypeError, ValueError) as exc:
        out.append(f"{proto.name}: a sanitised section is not JSON "
                   f"(message {index}): {exc}")
    return out


def _check_packet_round_trip(
    proto: AppProtocol, message: object, transport: str, index: int,
) -> list[str]:
    """Check a whole packet survives being built, parsed and rebuilt.

    The guarantee packeteer exists for, asserted here once for both ways of
    producing a protocol rather than twice in different files.
    """
    from packeteer.generate import PacketBuilder
    from packeteer.parse import parse_packet

    port = min(proto.ports) if proto.ports else 9999
    def frame_for(msg: object) -> bytes:
        builder = (PacketBuilder()
                   .ethernet(src_mac="00:00:00:00:00:01",
                             dst_mac="00:00:00:00:00:02")
                   .ip(src="10.0.0.1", dst="10.0.0.2"))
        builder = (builder.tcp(src_port=40000, dst_port=port)
                   if transport == "tcp"
                   else builder.udp(src_port=40000, dst_port=port))
        return builder.app(msg).build()

    try:
        frame = frame_for(message)
    except _CODEC_ERRORS as exc:
        return [f"{proto.name}: building a packet (message {index}): "
                f"{type(exc).__name__}: {exc}"]

    parsed = parse_packet(frame)
    if parsed.app is None:
        return [f"{proto.name}: a built packet did not decode back "
                f"(message {index}); does the protocol claim port {port} on "
                f"{transport}?"]
    if parsed.app != message:
        return [f"{proto.name}: a built packet parsed back into a different "
                f"message (message {index})"]
    try:
        rebuilt = frame_for(proto.from_spec(proto.to_spec(parsed.app)))
    except _CODEC_ERRORS as exc:
        return [f"{proto.name}: rebuilding from a spec (message {index}): "
                f"{type(exc).__name__}: {exc}"]
    if rebuilt != frame:
        return [f"{proto.name}: a packet did not rebuild byte for byte "
                f"through its spec (message {index}): {len(frame)} bytes in, "
                f"{len(rebuilt)} out"]
    return []


def _check_registry(
    proto: AppProtocol, messages: Sequence[object], transport: str,
) -> list[str]:
    """Check that the registry resolves the protocol every way it should."""
    out: list[str] = []
    if protocols.for_section(proto.name) is not proto:
        out.append(f"{proto.name}: for_section does not resolve to it; is it "
                   f"registered?")
    for message in messages:
        # An instance, not its type: matching is by isinstance, so a subclass
        # of a registered message type resolves to the same protocol.
        found = protocols.for_message(message)
        if found is not proto:
            name = type(message).__name__
            out.append(f"{proto.name}: for_message({name}) resolved to "
                       f"{found.name if found else None!r}; is it listed in "
                       f"'messages'?")
    for port in sorted(proto.ports):
        found = protocols.for_port(port, transport)
        if found is not proto:
            out.append(f"{proto.name}: for_port({port}, {transport!r}) "
                       f"resolved to {found.name if found else None!r}")
    return out
