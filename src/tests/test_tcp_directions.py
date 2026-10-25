"""A TCP stream sends each message from its own side (#198).

`generate_tcp_stream` sent all its data from the client, so a DNS-over-TCP
stream replayed from queries and responses put the responses in the
client's byte stream, and the CLI refused such input rather than send it
wrong.  ``TCPStreamConfig.messages`` sends each message from its own side,
acknowledged by the other, split at the peer's MSS when it is longer.

The checks here are made on the packets as a reader of the capture would
make them, not on the generator's state: every acknowledgement is held to
what the peer had delivered by then, and each direction's bytes, put back
together by sequence number, are that side's messages in order.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.session_mix import generate_session_mix
from packeteer.generate.tcp import DEFAULT_MSS, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN, TCPOptions
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.parse import parse_packet

_WRAP = 2 ** 32
_CLIENT = ("10.0.0.2", 54321, "00:00:00:00:00:01")
_SERVER = ("10.0.0.1", 53, "00:00:00:00:00:02")
_SEEDS = range(30)

#: SHA-256 of a seeded, lossy, recovered stream without messages, computed
#: on b6f16df before #198.
_PLAIN_SEED_7 = "e0f957ae8604edfc8ff3cd8049345804ea939000ae32d9958b212d7766aea478"

#: Impairments under which every byte still arrives: lost segments are
#: retransmitted, corrupted ones resent clean, and copies are copies.
_COMPLETE = {
    "clean": {},
    "loss, recovered": {"packet_loss_probability": 0.3, "retransmit_lost": True},
    "spurious retransmission": {"retransmission_probability": 0.3},
    "corruption": {"payload_corruption_probability": 0.3},
    "duplication": {"duplicate_probability": 0.3},
    "all of them": {"packet_loss_probability": 0.2, "retransmit_lost": True,
                    "retransmission_probability": 0.2,
                    "payload_corruption_probability": 0.2,
                    "duplicate_probability": 0.2},
}
#: And the ones that leave holes or end the connection early.
_PARTIAL = {
    "loss": {"packet_loss_probability": 0.3},
    "server RST": {"server_rst_probability": 1.0},
    "strays": {"stray_packet_count": 2},
}


def _message(direction: str, index: int, size: int) -> AppMessage:
    """Return a message whose bytes say which one it is, to the byte."""
    head = f"{direction}:{index:04d}|".encode()
    return AppMessage(direction, (head * (size // len(head) + 1))[:size], f"m[{index}]")


#: A conversation with replies, one of them longer than any segment.
_CONVERSATION = [
    _message("c2s", 0, 40), _message("s2c", 1, 300),
    _message("c2s", 2, 120), _message("s2c", 3, 4000),
    _message("s2c", 4, 90), _message("c2s", 5, 60),
]


def _stream(seed: int, **config: object) -> list:
    return generate_tcp_stream(
        client_ip=_CLIENT[0], server_ip=_SERVER[0], server_port=_SERVER[1],
        num_data_packets=len(_CONVERSATION),
        config=TCPStreamConfig(seed=seed, base_time=1e9, messages=_CONVERSATION,
                               **config),
    ).packets


def _usec(pkt: object) -> int:
    return pkt.ts_sec * 1_000_000 + pkt.ts_usec


def _seq_len(pkt: object) -> int:
    return pkt.payload_len + bool(pkt.flags & TCP_SYN) + bool(pkt.flags & TCP_FIN)


def _later(a: int, b: int) -> bool:
    return 0 < (a - b) % _WRAP < _WRAP // 2


def _forged(pkt: object) -> bool:
    """Whether *pkt* never reached the stack it was sent to as sent.

    A stray, or a corrupted copy, which fails its checksum and is dropped.
    The capture point's duplicate of either, ``DUP[CORRUPT[...]]``, is no
    better.
    """
    return "STRAY[" in pkt.label or "CORRUPT[" in pkt.label


def _mirrored(pkt: object) -> bool:
    """Whether *pkt* is the capture point's copy of a packet already seen.

    It carries its original's acknowledgement, from the original's moment,
    so it is checked as the original is, not against what arrived in the
    microsecond between them.
    """
    return pkt.label.startswith("DUP[")


def _rcv_nxt(packets: list, peer: str, before: int) -> int:
    """Return the end of *peer*'s bytes delivered in order before *before*."""
    syn = next(p for p in packets if p.direction == peer and p.flags & TCP_SYN)
    edge = (syn.seq + 1) % _WRAP
    ranges = [(p.seq, (p.seq + _seq_len(p)) % _WRAP) for p in packets
              if p.direction == peer and _seq_len(p) and p is not syn
              and not _forged(p) and _usec(p) < before]
    moved = True
    while moved:
        moved = False
        for begin, end in ranges:
            if not _later(begin, edge) and _later(end, edge):
                edge, moved = end, True
    return edge


#: The inter-packet gap the streams here use, in microseconds.
_GAP_USEC = 1000


def _acceptable(packets: list, peer: str, at: int) -> set[int]:
    """Return the ACK values a packet captured at *at* may carry.

    What *peer* had delivered in order at some moment in the last gap: at
    least everything before ``at - gap``, at most everything before *at*.
    """
    moments = {at, at - _GAP_USEC}
    moments |= {_usec(p) + 1 for p in packets
                if p.direction == peer and at - _GAP_USEC <= _usec(p) < at}
    return {_rcv_nxt(packets, peer, moment) for moment in moments}


def _payload(pkt: object) -> bytes:
    data = parse_packet(pkt.raw)
    return data.payload if data.payload else b""


def _reassembled(packets: list, direction: str) -> bytes:
    """One direction's bytes, put back together by sequence number."""
    syn = next(p for p in packets if p.direction == direction and p.flags & TCP_SYN)
    start = (syn.seq + 1) % _WRAP
    pieces = {}
    for p in packets:
        if p.direction == direction and p.payload_len and not _forged(p):
            pieces[(p.seq - start) % _WRAP] = _payload(p)
    out = bytearray()
    for offset in sorted(pieces):
        piece = pieces[offset]
        if offset > len(out):
            break
        out[offset:offset + len(piece)] = piece
    return bytes(out)


class TestEachMessageFromItsOwnSide(unittest.TestCase):

    def test_a_reply_is_sent_by_the_server_and_acknowledged_by_the_client(self) -> None:
        packets = _stream(1)
        data = [p for p in packets if p.payload_len]
        self.assertEqual({p.direction for p in data}, {"c2s", "s2c"})
        for p in packets:
            with self.subTest(label=p.label):
                pkt = parse_packet(p.raw)
                src, dst = (_CLIENT, _SERVER) if p.direction == "c2s" else (_SERVER, _CLIENT)
                self.assertEqual((pkt.ip.src, pkt.transport.src_port, pkt.ethernet.src_mac), src)
                self.assertEqual((pkt.ip.dst, pkt.transport.dst_port, pkt.ethernet.dst_mac), dst)
        for p in data:
            with self.subTest(segment=p.label):
                ack = next(q for q in packets if q.label == p.label.replace("DATA", "ACK", 1))
                self.assertNotEqual(ack.direction, p.direction)
                self.assertEqual(ack.ack, (p.seq + p.payload_len) % _WRAP)

    def test_each_direction_carries_its_own_messages_in_order(self) -> None:
        packets = _stream(1)
        for direction in ("c2s", "s2c"):
            expected = b"".join(m.data for m in _CONVERSATION if m.direction == direction)
            self.assertEqual(_reassembled(packets, direction), expected)

    def test_messages_cycle_to_make_up_the_count(self) -> None:
        packets = generate_tcp_stream(
            client_ip=_CLIENT[0], server_ip=_SERVER[0], num_data_packets=5,
            config=TCPStreamConfig(seed=1, base_time=1e9, messages=[
                _message("c2s", 0, 20), _message("s2c", 1, 30)]),
        ).packets
        data = [p for p in packets if p.payload_len]
        self.assertEqual([p.direction for p in data], ["c2s", "s2c"] * 2 + ["c2s"])
        self.assertEqual([p.label for p in data], [f"DATA[{i}]" for i in range(5)])


class TestSegmenting(unittest.TestCase):

    def _segments(self, size: int, **config: object) -> list:
        packets = generate_tcp_stream(
            client_ip=_CLIENT[0], server_ip=_SERVER[0], num_data_packets=1,
            config=TCPStreamConfig(seed=1, base_time=1e9, psh_probability=1.0,
                                   messages=[_message("s2c", 0, size)], **config),
        ).packets
        return [p for p in packets if p.payload_len]

    def test_a_long_message_is_split_at_the_peers_mss_less_timestamps(self) -> None:
        # The default options negotiate timestamps, which take 12 bytes of
        # every segment.
        segments = self._segments(4000)
        limit = DEFAULT_MSS - 12
        self.assertEqual([p.payload_len for p in segments], [limit, limit, 4000 - 2 * limit])
        self.assertEqual([p.label for p in segments],
                         ["DATA[0] [1/3]", "DATA[0] [2/3]", "DATA[0] [3/3]"])

    def test_the_receivers_mss_is_what_counts(self) -> None:
        # A server message goes to the client, so the client's MSS limits it.
        segments = self._segments(
            1000, client_options=TCPOptions(mss=400), server_options=TCPOptions(mss=1460),
        )
        self.assertEqual([p.payload_len for p in segments], [400, 400, 200])

    def test_without_options_the_default_mss_and_no_timestamps(self) -> None:
        segments = self._segments(3000, client_options=None, server_options=None)
        self.assertEqual([p.payload_len for p in segments],
                         [DEFAULT_MSS, DEFAULT_MSS, 3000 - 2 * DEFAULT_MSS])

    def test_psh_is_only_ever_on_the_last_segment(self) -> None:
        segments = self._segments(4000)
        self.assertEqual([bool(p.flags & TCP_PSH) for p in segments], [False, False, True])
        packets = generate_tcp_stream(
            client_ip=_CLIENT[0], server_ip=_SERVER[0], num_data_packets=1,
            config=TCPStreamConfig(seed=1, base_time=1e9, psh_probability=0.0,
                                   messages=[_message("s2c", 0, 4000)]),
        ).packets
        self.assertFalse(any(p.flags & TCP_PSH for p in packets))

    def test_a_message_that_fits_is_one_segment(self) -> None:
        segments = self._segments(DEFAULT_MSS - 12)
        self.assertEqual([p.label for p in segments], ["DATA[0]"])


class TestEveryImpairmentBothWays(unittest.TestCase):

    def _streams(self, impairments: dict) -> list:
        return [(f"{name}, seed {seed}", _stream(seed, **config))
                for name, config in impairments.items() for seed in _SEEDS]

    def test_every_acknowledgement_is_what_the_peer_had_delivered(self) -> None:
        # What the peer had delivered in order when it was captured, give or
        # take a segment crossing the ACK in flight: during recovery, the
        # ACK of one retransmission can be captured just after the next
        # retransmission, which its sender had not yet received.  So an ACK
        # may lag what arrived in the last inter-packet gap, and must count
        # everything before it.  A capture-point copy is checked as its
        # original, and a forged or corrupted segment delivers nothing.
        for name, packets in self._streams({**_COMPLETE, **_PARTIAL}):
            for p in packets:
                if (p.flags & (TCP_SYN | TCP_RST) or _forged(p) or _mirrored(p)
                        or not p.flags & 0x10):
                    continue
                peer = "s2c" if p.direction == "c2s" else "c2s"
                with self.subTest(stream=name, packet=p.label):
                    self.assertIn(p.ack, _acceptable(packets, peer, _usec(p)))

    def test_every_byte_arrives_once_on_its_own_side(self) -> None:
        for name, packets in self._streams(_COMPLETE):
            for direction in ("c2s", "s2c"):
                with self.subTest(stream=name, direction=direction):
                    expected = b"".join(m.data for m in _CONVERSATION
                                        if m.direction == direction)
                    self.assertEqual(_reassembled(packets, direction), expected)

    def test_a_lost_server_segment_draws_duplicate_acks_from_the_client(self) -> None:
        found = False
        for _, packets in self._streams({"loss": _PARTIAL["loss"]}):
            client_acks = [p.ack for p in packets
                           if p.direction == "c2s" and p.flags == 0x10 and not p.payload_len]
            if len(client_acks) != len(set(client_acks)):
                found = True
                break
        self.assertTrue(found, "no seed lost a server segment")

    def test_strays_and_rst_come_from_the_right_side(self) -> None:
        for name, packets in self._streams({k: _PARTIAL[k] for k in ("server RST", "strays")}):
            for p in packets:
                if p.label.startswith("STRAY[") or p.flags & TCP_RST:
                    with self.subTest(stream=name, packet=p.label):
                        src = parse_packet(p.raw).ip.src
                        self.assertEqual(src, _CLIENT[0] if p.direction == "c2s" else _SERVER[0])
                        if p.flags & TCP_RST:
                            self.assertEqual(p.direction, "s2c")


class TestTheConfig(unittest.TestCase):

    def test_messages_with_payload_fn_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "payload_fn or messages, not both"):
            generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2", config=TCPStreamConfig(
                messages=[_message("c2s", 0, 10)], payload_fn=lambda i, d: b"x"))

    def test_empty_messages_are_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty: nothing to send"):
            generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                                config=TCPStreamConfig(messages=[]))
        with self.assertRaisesRegex(ValueError, r"messages\[1\] is empty"):
            generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                                config=TCPStreamConfig(messages=[
                                    _message("c2s", 0, 10), AppMessage("s2c", b"", "x")]))

    def test_a_bad_direction_is_refused(self) -> None:
        with self.assertRaisesRegex(ValueError, r"messages\[0\]: direction must be"):
            generate_tcp_stream(client_ip="10.0.0.1", server_ip="10.0.0.2",
                                config=TCPStreamConfig(messages=[AppMessage("up", b"x", "x")]))

    def test_payload_sizes_are_ignored_beside_messages(self) -> None:
        sized = _stream(3, payload_sizes=[1] * len(_CONVERSATION))
        self.assertEqual([p.raw for p in sized], [p.raw for p in _stream(3)])

    def test_client_only_messages_are_what_a_payload_fn_sends(self) -> None:
        # The CLI moved from payload_fn to messages on TCP, so a conversation
        # with no replies must give the same bytes, impaired or not.
        given = [_message("c2s", i, 50 + 30 * i) for i in range(4)]
        for extra in ({}, {"packet_loss_probability": 0.3, "retransmit_lost": True,
                           "payload_corruption_probability": 0.2, "gap_jitter": 0.002}):
            with self.subTest(impairments=sorted(extra)):
                streams = [generate_tcp_stream(
                    client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=7,
                    config=TCPStreamConfig(seed=9, base_time=1e9, **extra, **source),
                ).packets for source in (
                    {"messages": given},
                    {"payload_fn": lambda i, _d: given[i % len(given)].data},
                )]
                self.assertEqual([p.raw for p in streams[0]], [p.raw for p in streams[1]])

    def test_a_stream_without_messages_is_unchanged(self) -> None:
        # Computed on b6f16df, before #198.
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=8,
            config=TCPStreamConfig(seed=7, base_time=1e9, packet_loss_probability=0.2,
                                   retransmit_lost=True),
        )
        digest = hashlib.sha256(b"".join(p.raw for p in stream.packets)).hexdigest()
        self.assertEqual(digest, _PLAIN_SEED_7)

    def test_sessions_carry_the_messages(self) -> None:
        # generate_session_mix replaces the config per session, so messages
        # ride along to every one, as #194 found impairments do.
        mix = generate_session_mix(
            sessions=3, client_ip=_CLIENT[0], server_ip="10.0.1.1", server_port=53,
            num_data_packets=len(_CONVERSATION),
            config=TCPStreamConfig(seed=2, base_time=1e9, messages=_CONVERSATION),
        )
        replies = {parse_packet(p.raw).ip.src for p in mix.packets
                   if p.payload_len and p.direction == "s2c"}
        self.assertEqual(replies, {"10.0.1.1", "10.0.1.2", "10.0.1.3"})


def _packeteer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "packeteer", *args],
                          capture_output=True, text=True, check=False)


class TestTheIssuesAcceptance(unittest.TestCase):
    """A parsed DNS-over-TCP capture with queries and responses replays both ways."""

    _COMMON = ("--protocol", "tcp", "--payload", "dns",
               "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
               "--server-port", "53", "--seed", "5", "--packets", "6")

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        query = {"id": 1, "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}]}
        response = {**query, "flags": {"qr": True},
                    "answers": [{"name": "www.example.com.", "rtype": 1, "rclass": 1,
                                 "ttl": 60, "rdata": {"address": "192.0.2.7"}}]}
        given = self.dir / "given.json"
        given.write_text(json.dumps([{"dns": query}, {"dns": response, "direction": "s2c"}]))
        capture = self.dir / "capture.pcap"
        done = _packeteer("stream", *self._COMMON, "--protocol-messages", str(given),
                          "--pcap", str(capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        # Replayed from what parse writes, which carries no direction: it is
        # read from the addresses, port 53 being the server's.
        self.parsed = self.dir / "parsed.json"
        done = _packeteer("parse", str(capture), "--output", str(self.parsed))
        self.assertEqual(done.returncode, 0, done.stderr)

    def _replay(self, *extra: str) -> list:
        out = self.dir / "replay.json"
        done = _packeteer("stream", *self._COMMON, "--protocol-messages", str(self.parsed),
                          *extra, "--json", str(out))
        self.assertEqual(done.returncode, 0, done.stderr)
        return json.loads(out.read_text())["packets"]

    def test_each_response_is_in_the_servers_byte_stream(self) -> None:
        packets = self._replay()
        dns = [p for p in packets if "dns" in p]
        self.assertEqual([p["packet_metadata"]["direction"] for p in dns], ["c2s", "s2c"] * 3)
        for p in dns:
            query = p["packet_metadata"]["direction"] == "c2s"
            self.assertEqual(p["network"]["src"], "10.0.0.2" if query else "10.0.0.1")
            self.assertEqual(bool(p["dns"].get("flags", {}).get("qr")), not query)

    def test_parse_of_the_result_gives_back_the_directions(self) -> None:
        pcap = self.dir / "both.pcap"
        done = _packeteer("stream", *self._COMMON, "--protocol-messages", str(self.parsed),
                          "--pcap", str(pcap))
        self.assertEqual(done.returncode, 0, done.stderr)
        reparsed = self.dir / "reparsed.json"
        done = _packeteer("parse", str(pcap), "--output", str(reparsed))
        self.assertEqual(done.returncode, 0, done.stderr)
        dns = [p for p in json.loads(reparsed.read_text())["packets"] if "dns" in p]
        self.assertEqual([p["network"]["src"] for p in dns], ["10.0.0.2", "10.0.0.1"] * 3)

    def test_with_loss_both_sides_draw_duplicate_acks(self) -> None:
        sides = set()
        for seed in range(12):
            packets = self._replay("--packet-loss", "0.3", "--seed", str(seed))
            for direction in ("c2s", "s2c"):
                acks = [p["transport"]["ack"] for p in packets
                        if p["packet_metadata"]["direction"] == direction
                        and "dns" not in p and "payload" not in p
                        and p["transport"].get("flags") == 0x10]
                if len(acks) != len(set(acks)):
                    sides.add(direction)
        self.assertEqual(sides, {"c2s", "s2c"})


def _server_stream(pcap: Path) -> bytes:
    """Return the payload bytes port 53 sent in *pcap*, in capture order."""
    from packeteer.pcap import read_pcap
    out = b""
    for record in read_pcap(path=pcap).packets:
        pkt = parse_packet(record.data, decode_app=False)
        if pkt.transport is not None and pkt.transport.src_port == 53:
            out += pkt.payload
    return out


def _parsed_packet(src_port: int, dst_port: int, **sections: object) -> dict:
    """Return a packet as `packeteer parse` writes it; .1 is the server."""
    src, dst = ("10.0.0.2", "10.0.0.1") if dst_port in (53, 443) else ("10.0.0.1", "10.0.0.2")
    return {"network": {"src": src, "dst": dst, "protocol": "tcp"},
            "transport": {"src_port": src_port, "dst_port": dst_port}, **sections}


class TestAMessageParseCouldNotDecodeIsRefused(unittest.TestCase):
    """#220: a message split over segments was dropped, and the list cycled."""

    _QUERY = {"id": 1, "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}]}

    def _dns(self) -> object:
        from packeteer import protocols
        return protocols.for_section("dns")

    def test_the_issues_reproduction(self) -> None:
        # A 3,234-byte response, generated, parsed and replayed.  parse
        # writes it as three payload-only segments from port 53.
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        q = "076170696461746111676f6f676c6575736572636f6e74656e7403636f6d0000010001"
        bulk = "0462756c6b076578616d706c6503636f6d0000010001"
        given = [
            {"dns": {"raw": "0b0a01000001000000000000" + q}},
            {"dns": {"raw": "22228180000100c800000000" + bulk + "".join(
                f"c00c000100010000003c00040a0000{i:02x}" for i in range(200))},
             "direction": "s2c"},
        ]
        (tmp / "given.json").write_text(json.dumps(given))
        common = ("--protocol", "tcp", "--payload", "dns", "--server-port", "53",
                  "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
                  "--packets", "2", "--seed", "5")
        done = _packeteer("stream", *common, "--protocol-messages", str(tmp / "given.json"),
                          "--pcap", str(tmp / "a.pcap"))
        self.assertEqual(done.returncode, 0, done.stderr)
        done = _packeteer("parse", str(tmp / "a.pcap"), "--output", str(tmp / "a.json"))
        self.assertEqual(done.returncode, 0, done.stderr)
        done = _packeteer("stream", *common, "--protocol-messages", str(tmp / "a.json"),
                          "--json", str(tmp / "c.json"))
        self.assertEqual(done.returncode, 1)
        # The message, 3,234 bytes, plus DNS over TCP's 2-byte length prefix.
        self.assertIn("3 packet(s) on the dns flow", done.stderr)
        self.assertIn("carry 3236 bytes of payload but no 'dns' section", done.stderr)
        self.assertIn("(s2c, 1448 bytes)", done.stderr)
        # #223: on TCP both causes are given, the split one first.
        self.assertIn("on its own: split over TCP segments, which parse does not join, "
                      "or malformed, truncated, or not dns at all", done.stderr)
        self.assertFalse((tmp / "c.json").exists())
        # #222: the payload counts the length field; the error also gives
        # the message's own size, and says raw leaves the field out.
        self.assertIn("The packets at index 5, 7, 9 (s2c) are together one "
                      "3234-byte dns message, after the 2-byte length field TCP adds",
                      done.stderr)
        self.assertIn("'raw' is the message without that field", done.stderr)

        # Following the error as written: the joined payloads, less the
        # 2 bytes it names, as a wrapped raw section.  The server's byte
        # stream comes out as the original's, not double-prefixed.
        parsed = json.loads((tmp / "a.json").read_text())["packets"]
        joined = b"".join(bytes.fromhex(p["payload"]["data"]) for p in parsed
                          if "payload" in p and "dns" not in p)
        fixed = [p for p in parsed if "dns" in p]
        fixed.append({"dns": {"raw": joined[2:].hex()}, "direction": "s2c"})
        (tmp / "fixed.json").write_text(json.dumps(fixed))
        done = _packeteer("stream", *common, "--protocol-messages", str(tmp / "fixed.json"),
                          "--pcap", str(tmp / "f.pcap"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(_server_stream(tmp / "f.pcap"), _server_stream(tmp / "a.pcap"))

    def test_every_reader_refuses(self) -> None:
        from packeteer.app import protocol_conversation, protocol_messages, protocol_payload_fn
        given = [_parsed_packet(54321, 53, dns=self._QUERY),
                 _parsed_packet(53, 54321, payload={"data": "00" * 40})]
        for reader in (protocol_conversation, protocol_payload_fn, protocol_messages):
            with self.subTest(reader=reader.__name__), self.assertRaises(ValueError) as caught:
                reader(self._dns(), given, "tcp")
            self.assertIn("at index 1 (s2c, 40 bytes)", str(caught.exception))

    def test_undecodable_on_udp_too(self) -> None:
        from packeteer.app import protocol_conversation
        given = [_parsed_packet(54321, 53, dns=self._QUERY),
                 _parsed_packet(54321, 53, payload={"data": "not dns", "encoding": "utf8"})]
        with self.assertRaises(ValueError) as caught:
            protocol_conversation(self._dns(), given, "udp")
        self.assertIn("at index 1 (c2s, 7 bytes)", str(caught.exception))
        # #223: nothing is split on UDP, and the error does not say it is.
        self.assertIn("could not decode it as a dns message: malformed, truncated, "
                      "or not dns at all", str(caught.exception))
        self.assertNotIn("TCP", str(caught.exception))
        self.assertNotIn("segment", str(caught.exception))

    def _framed(self, section: dict) -> bytes:
        """Return *section* as DNS over TCP sends it, length field first."""
        dns = self._dns()
        return dns.encode(dns.from_spec(section), "tcp")

    def _refusal(self, payloads: list[bytes], transport: str = "tcp") -> str:
        from packeteer.app import protocol_conversation
        given = [_parsed_packet(54321, 53, dns=self._QUERY)]
        given += [_parsed_packet(53, 54321, payload={"data": b.hex()}) for b in payloads]
        with self.assertRaises(ValueError) as caught:
            protocol_conversation(self._dns(), given, transport)
        return str(caught.exception)

    def test_a_partial_message_gets_no_size(self) -> None:
        # #222: only a run that is exactly one message is sized.
        whole = self._framed(self._QUERY)
        self.assertNotIn("are together one", self._refusal([whole[:10], whole[10:-3]]))
        self.assertIn("are together one", self._refusal([whole[:10], whole[10:]]))

    def test_two_messages_in_one_run_get_no_size(self) -> None:
        whole = self._framed(self._QUERY)
        both = whole + whole
        self.assertNotIn("are together one", self._refusal([both[:20], both[20:]]))

    def test_udp_has_no_length_field_to_explain(self) -> None:
        # Kober's truncated datagram again: on UDP nothing is framed.
        message = self._refusal([self._framed(self._QUERY)[2:12]], transport="udp")
        self.assertNotIn("length field", message)
        self.assertNotIn("are together one", message)

    def test_kobers_udp_reproduction(self) -> None:
        """#223: a truncated response datagram, generated, parsed and replayed."""
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, tmp, True)
        q = "076170696461746111676f6f676c6575736572636f6e74656e7403636f6d0000010001"
        query, response = "0b0a01000001000000000000" + q, "0b0a81800001000000000000" + q
        (tmp / "given.json").write_text(json.dumps([
            {"dns": {"raw": query}}, {"dns": {"raw": response}, "direction": "s2c"},
            {"dns": {"raw": response[:20]}, "direction": "s2c"},
        ]))
        common = ("--protocol", "udp", "--payload", "dns", "--server-port", "53",
                  "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
                  "--packets", "3", "--seed", "1")
        done = _packeteer("stream", *common, "--protocol-messages", str(tmp / "given.json"),
                          "--pcap", str(tmp / "u.pcap"))
        self.assertEqual(done.returncode, 0, done.stderr)
        done = _packeteer("parse", str(tmp / "u.pcap"), "--output", str(tmp / "u.json"))
        self.assertEqual(done.returncode, 0, done.stderr)
        done = _packeteer("stream", *common, "--protocol-messages", str(tmp / "u.json"),
                          "--pcap", str(tmp / "u2.pcap"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("at index 2 (s2c, 10 bytes)", done.stderr)
        self.assertIn("malformed, truncated, or not dns at all", done.stderr)
        self.assertNotIn("TCP", done.stderr)

    def test_another_flow_and_packets_with_no_payload_are_skipped(self) -> None:
        from packeteer.app import protocol_conversation
        given = [_parsed_packet(54321, 53),                                  # an ACK
                 _parsed_packet(40000, 443, payload={"data": "16030100"}),   # TLS beside it
                 _parsed_packet(54321, 53, dns=self._QUERY)]
        messages = protocol_conversation(self._dns(), given, "tcp")
        self.assertEqual([m.direction for m in messages], ["c2s"])


if __name__ == "__main__":
    unittest.main()
