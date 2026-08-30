"""A chunked body keeps its framing, and why that is the right answer (#84)."""
from __future__ import annotations

import json
import unittest
import warnings
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.generate.http import HTTPResponse, _build_http_message
from packeteer.parse import parse_packet, parse_pcap_file
from packeteer.parse.http import parse_http
from packeteer.pcap import open_pcap

_CORPUS = Path(__file__).resolve().parents[2] / "testcases" / "real"

_CHUNKED = (b"HTTP/1.1 200 OK\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"4\r\nabcd\r\n0\r\n\r\n")


class TestTheBodyKeepsItsFraming(unittest.TestCase):
    """`body` is the encoded body — the bytes on the wire, not the payload."""

    def test_the_chunk_sizes_and_terminator_are_still_there(self) -> None:
        self.assertEqual(parse_http(_CHUNKED).body, b"4\r\nabcd\r\n0\r\n\r\n")

    def test_a_content_length_body_is_trimmed_as_before(self) -> None:
        """The control: framing is kept, not everything after the headers."""
        message = parse_http(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nabcdEXTRA")
        self.assertEqual(message.body, b"abcd")


class TestWhyItIsNotDeChunked(unittest.TestCase):
    """The argument, asserted rather than only written down.

    Chunk boundaries are a sender's choice, not a property of the payload.
    Two chunkings of the same bytes are different on the wire and identical
    afterwards, so a de-chunked body cannot be re-chunked to reproduce the
    capture it came from — which is the guarantee packeteer exists to give.

    The splits are `1c/c/18/6` and `40/6`, both summing to 70.  The issue's
    illustration says `1c/c/18/4`, which sums to 68; the argument is the same
    either way, but a test has to add up.
    """

    _PAYLOAD = b"x" * 70

    def _chunked(self, *sizes: int) -> bytes:
        out, offset = b"", 0
        for size in sizes:
            out += f"{size:x}\r\n".encode() + self._PAYLOAD[offset:offset + size] + b"\r\n"
            offset += size
        return out + b"0\r\n\r\n"

    def _dechunk(self, body: bytes) -> bytes:
        out, rest = b"", body
        while True:
            head, _, rest = rest.partition(b"\r\n")
            size = int(head, 16)
            if size == 0:
                return out
            out, rest = out + rest[:size], rest[size + 2:]

    def test_two_chunkings_differ_on_the_wire(self) -> None:
        self.assertNotEqual(self._chunked(0x1c, 0xc, 0x18, 0x6),
                            self._chunked(0x40, 0x6))

    def test_and_are_identical_once_de_chunked(self) -> None:
        """So de-chunking loses exactly what a rebuild would need."""
        self.assertEqual(self._dechunk(self._chunked(0x1c, 0xc, 0x18, 0x6)),
                         self._dechunk(self._chunked(0x40, 0x6)))
        self.assertEqual(self._dechunk(self._chunked(0x40, 0x6)), self._PAYLOAD)

    def test_keeping_the_framing_is_what_makes_the_round_trip_work(self) -> None:
        for sizes in ((0x1c, 0xc, 0x18, 0x6), (0x40, 0x6)):
            with self.subTest(sizes=sizes):
                raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       + self._chunked(*sizes))
                self.assertEqual(_build_http_message(parse_http(raw)), raw)


class TestAWholePacketRoundTrips(unittest.TestCase):
    """The property the decision protects, through a packet and a spec."""

    def _frame(self, body: bytes) -> bytes:
        message = HTTPResponse(status_code=200, reason="OK",
                               headers={"Transfer-Encoding": "chunked"},
                               body=body)
        return (PacketBuilder()
                .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                .ip(src="10.0.0.1", dst="10.0.0.2")
                .tcp(src_port=80, dst_port=40000)
                .app(message).build())

    def test_a_chunked_response_rebuilds_byte_for_byte(self) -> None:
        frame = self._frame(b"4\r\nabcd\r\n0\r\n\r\n")
        parsed = parse_packet(frame)
        self.assertEqual(parsed.http.body, b"4\r\nabcd\r\n0\r\n\r\n")
        self.assertEqual(self._frame(parsed.http.body), frame)


class TestRealChunkedTraffic(unittest.TestCase):
    """Asserted against bytes nobody wrote for packeteer (#127's capture)."""

    def _spec(self) -> dict:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return json.loads(parse_pcap_file(path=str(_CORPUS / "http_body.pcap")))

    def test_the_capture_carries_a_chunked_body(self) -> None:
        responses = [p["http"] for p in self._spec()["packets"]
                     if p.get("http", {}).get("type") == "response"]
        self.assertTrue(responses)
        body = responses[0]
        self.assertEqual(body["headers"].get("Transfer-Encoding"), "chunked")
        decoded = bytes.fromhex(body["body"])
        self.assertRegex(decoded.decode("latin-1"), r"^[0-9a-fA-F]+\r\n",
                         "the body should still start with a chunk header")

    def test_and_every_packet_rebuilds_identically(self) -> None:
        """Real chunked traffic, through a spec and back, unchanged."""
        path = _CORPUS / "http_body.pcap"
        spec = self._spec()
        with open_pcap(path=str(path)) as capture:
            originals = [record.data for record in capture]
        for index, (packet, original) in enumerate(
            zip(spec["packets"], originals, strict=True), start=1,
        ):
            with self.subTest(packet=index):
                builder, _ = cli._apply_spec_to_builder(PacketBuilder(), packet, index)
                self.assertEqual(builder.build().hex(), original.hex())


if __name__ == "__main__":
    unittest.main()
