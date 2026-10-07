"""A sanitised TCP segment keeps its payload length (#191).

`sanitise` rebuilds each packet with the sequence number it was captured
with.  A segment whose payload changed size leaves every sequence number
after it false, and a reassembler then finds bytes missing or overlapping
that the capture never had: a gap is a statement that bytes were lost, and a
decoder resynchronises after one.  So whatever `sanitise` redacts, it must
redact at the same length.

This is a property over every capture rather than a case, since the faults
of this kind were found one at a time: `[redacted]` in a header (before
0.17.0) and in a chunked trailer (#189).  Every address and port replacement
keeps its size, so a TCP packet built from the sanitised spec is the length
of the one built from the parsed spec exactly when its payload is.

DNS over TCP is left out of the generated streams: label redaction changes a
DNS message's length, and that is #192.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import parse_pcap_file
from packeteer.sanitise import SanitiseOptions, sanitise

_CORPUS = Path(__file__).resolve().parents[2] / "testcases" / "real"

#: Each flag that rewrites an application section, alone and together, and
#: the defaults, which rewrite addresses.
_OPTIONS = {
    "defaults": {},
    "--http-headers": {"http_headers": True},
    "--payload": {"payload": True},
    "--http-headers --payload": {"http_headers": True, "payload": True},
}


def _tcp_lengths(config: dict) -> dict[int, int]:
    """Return each TCP packet's built length, by its index in *config*."""
    lengths: dict[int, int] = {}
    for index, spec in enumerate(config["packets"], 1):
        if spec.get("network", {}).get("protocol") != "tcp":
            continue
        builder, _ = cli._apply_spec_to_builder(PacketBuilder(), spec, index)
        lengths[index] = len(builder.build())
    return lengths


def _http_capture(directory: Path) -> Path:
    """Write a capture of HTTP that every flag has something to rewrite in.

    Given `raw` messages with sensitive headers of many lengths, a chunked
    body with an extension and a checksum trailer, and a body to zero; then
    generated REST traffic, which carries `Host` and `Authorization`.
    """
    request = (b"POST /login HTTP/1.1\r\nHost: shop.example.com\r\n"
               b"Authorization: Bearer abc\r\nCookie: a=1\r\n"
               b"Content-Length: 11\r\n\r\nuser=alice!")
    response = (b"HTTP/1.1 200 OK\r\nSet-Cookie: session=abc; Expires=Wed, 21 Oct 2026"
                b" 07:28:00 GMT\r\nSet-Cookie: b=2\r\nTransfer-Encoding: chunked\r\n\r\n"
                b"7;sig=SECRETE\r\nSECRETA\r\n0\r\nX-Checksum: 35308ec29a10ff4d\r\n\r\n")
    messages = directory / "m.json"
    messages.write_text(json.dumps([{"http": {"raw": request.hex()}},
                                    {"http": {"raw": response.hex()}}]))
    given, generated = directory / "given.pcap", directory / "generated.pcap"
    common = ("--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1", "--seed", "1")
    # One segment per message, so the chunked body is walked and its trailer
    # redacted; a body that spans segments is zeroed whole (#187), at its
    # length, and would test nothing here.
    for out, extra in ((given, ("--protocol-messages", str(messages), "--requests", "3")),
                       (generated, ("--requests", "20", "--chunked-rate", "1.0",
                                    "--trailer-rate", "1.0"))):
        done = subprocess.run(
            [sys.executable, "-m", "packeteer", "stream", "--payload", "http",
             *common, *extra, "--pcap", str(out)],
            capture_output=True, text=True, check=False,
        )
        assert done.returncode == 0, done.stderr
    return directory


class TestARedactionKeepsTheValuesLength(unittest.TestCase):

    def test_padded_cut_and_empty(self) -> None:
        from packeteer.sanitise import _redaction

        self.assertEqual(_redaction(16), "[redacted]      ")
        self.assertEqual(_redaction(10), "[redacted]")
        self.assertEqual(_redaction(4), "[red")
        self.assertEqual(_redaction(0), "")

    def test_a_parser_still_reads_redacted(self) -> None:
        """Trailing spaces in a header value are optional whitespace."""
        from packeteer.parse.http import parse_http

        msg = parse_http(b"GET / HTTP/1.1\r\nHost: [redacted]      \r\n\r\n")
        self.assertEqual(msg.headers["Host"], "[redacted]")


class TestEveryTCPSegmentKeepsItsLength(unittest.TestCase):

    def _check(self, path: Path) -> None:
        config = json.loads(parse_pcap_file(path=path))
        before = _tcp_lengths(config)
        for label, options in _OPTIONS.items():
            with self.subTest(capture=path.name, options=label):
                after = _tcp_lengths(sanitise(
                    config, SanitiseOptions(scan_pii=False, **options)))
                changed = {i: (before[i], after[i]) for i in before
                           if before[i] != after.get(i)}
                self.assertEqual(changed, {}, "packet: (before, after)")

    def test_the_real_capture_corpus(self) -> None:
        captures = sorted(_CORPUS.glob("*.pcap*"))
        self.assertGreater(len(captures), 20)
        for path in captures:
            self._check(path)

    def test_generated_http(self) -> None:
        """Where the redactions are: headers, cookies, a body, a trailer."""
        with tempfile.TemporaryDirectory() as tmp:
            directory = _http_capture(Path(tmp))
            for name in ("given.pcap", "generated.pcap"):
                self._check(directory / name)


if __name__ == "__main__":
    unittest.main()
