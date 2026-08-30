"""Driving a generated stream with a registered protocol (#119)."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
import warnings
from pathlib import Path

_SPEC = """
name: {name}
version: "1.0"
over: {over}
ports: [{port}]
input: datagram
entry: Reading
units:
  Reading:
    fields:
      - {{name: magic, type: {{int: {{bits: 16}}}}, const: 21317}}
      - {{name: owner, type: {{string: {{size: 8}}}}, sensitive: true}}
      - {{name: value, type: {{int: {{bits: 16}}}}}}
"""

_MESSAGES = [
    {"magic": 21317, "owner": "alice   ", "value": 21},
    {"magic": 21317, "owner": "bob     ", "value": 42},
]


def _packeteer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "packeteer", *args],
        capture_output=True, text=True, check=False,
    )


class _Workspace(unittest.TestCase):
    over = "udp"
    name = "sensor"
    port = 9000

    def setUp(self) -> None:
        import shutil

        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        (self.dir / "spec.yaml").write_text(textwrap.dedent(
            _SPEC.format(name=self.name, over=self.over, port=self.port)))
        done = _packeteer("protocol", "compile", str(self.dir / "spec.yaml"),
                          "-o", str(self.dir / "proto.py"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.module = self.dir / "proto.py"
        self.messages = self.dir / "msgs.json"
        self.messages.write_text(json.dumps(_MESSAGES))

    def _stream(self, *extra: str, packets: int = 5) -> subprocess.CompletedProcess:
        return _packeteer(
            "stream", "--load-protocol", str(self.module),
            "--protocol", self.over if self.over != "either" else "udp",
            "--payload", self.name,
            "--protocol-messages", str(self.messages),
            "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
            "--server-port", str(self.port),
            "--packets", str(packets), *extra,
        )

    def _sections(self, pcap: Path) -> list[dict]:
        from packeteer import protocols
        from packeteer.parse import iter_packets

        protocols.load_module(self.module)
        self.addCleanup(protocols.unregister, self.name)
        proto = protocols.for_section(self.name)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(pcap), defragment=False) as capture:
                return [proto.to_spec(p.app) for p in capture if p.app is not None]


class TestTheMessagesAreWhatWasAskedFor(_Workspace):
    """#119's acceptance: the data packets parse back into those messages."""

    def test_they_arrive_in_order(self) -> None:
        out = self.dir / "s.pcap"
        done = self._stream("--pcap", str(out), packets=2)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self._sections(out), _MESSAGES)

    def test_a_short_list_cycles(self) -> None:
        """--packets says how long the stream is; a short list must not shorten it."""
        out = self.dir / "s.pcap"
        done = self._stream("--pcap", str(out), packets=5)
        self.assertEqual(done.returncode, 0, done.stderr)
        sections = self._sections(out)
        self.assertEqual(len(sections), 5)
        self.assertEqual(sections, [_MESSAGES[i % 2] for i in range(5)])


class TestOverTCP(_Workspace):
    """The same, over a TCP session — and impairments must still apply."""

    over = "either"
    name = "sensor_tcp"
    port = 9002

    def _tcp_stream(self, *extra: str) -> subprocess.CompletedProcess:
        return _packeteer(
            "stream", "--load-protocol", str(self.module),
            "--protocol", "tcp", "--payload", self.name,
            "--protocol-messages", str(self.messages),
            "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
            "--server-port", str(self.port), "--packets", "6", *extra,
        )

    def test_the_data_packets_carry_the_messages(self) -> None:
        out = self.dir / "s.pcap"
        done = self._tcp_stream("--pcap", str(out))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self._sections(out)[:2], _MESSAGES)

    def test_impairments_still_apply(self) -> None:
        """Anomaly flags must not be silently dropped, as in #83.

        `--payload http` emitted labels the anomaly passes did not recognise,
        so every anomaly flag was ignored without a word.  Feeding payloads
        into the ordinary generator leaves the labels alone, which is why
        this route takes that shape rather than a path of its own.
        """
        out = self.dir / "s.json"
        done = self._tcp_stream("--retransmission-probability", "1.0",
                                "--seed", "7", "--json", str(out))
        self.assertEqual(done.returncode, 0, done.stderr)
        labels = [p["packet_metadata"].get("label")
                  for p in json.loads(out.read_text())["packets"]]
        self.assertIn("DATA[0]", labels, "the ordinary data labels are kept")
        self.assertTrue([lbl for lbl in labels if lbl and lbl.startswith("RETRANS")],
                        f"retransmissions should be injected: {labels}")


class TestTheBuiltInPayloadsStillWork(unittest.TestCase):
    """`--payload` stopped being a closed set; it must not have stopped working."""

    def test_http(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "http.pcap"
            done = _packeteer("stream", "--payload", "http", "--protocol", "tcp",
                              "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
                              "--requests", "2", "--pcap", str(out))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(out.stat().st_size > 0)

    def test_vpn(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "vpn.pcap"
            done = _packeteer("stream", "--payload", "vpn", "--protocol", "udp",
                              "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
                              "--packets", "4", "--pcap", str(out))
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertTrue(out.stat().st_size > 0)


class TestTheErrors(_Workspace):
    """Each failure names what to do about it."""

    def test_an_unregistered_name_lists_what_is_known(self) -> None:
        done = _packeteer("stream", "--payload", "nosuch", "--protocol", "udp",
                          "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
                          "--pcap", str(self.dir / "o.pcap"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("not a registered protocol", done.stderr)
        self.assertIn("--load-protocol", done.stderr)

    def test_the_wrong_transport_says_which_to_use(self) -> None:
        done = _packeteer(
            "stream", "--load-protocol", str(self.module),
            "--protocol", "tcp", "--payload", self.name,
            "--protocol-messages", str(self.messages),
            "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
            "--pcap", str(self.dir / "o.pcap"),
        )
        self.assertEqual(done.returncode, 1)
        self.assertIn("carried over udp", done.stderr)

    def test_missing_messages_says_what_is_needed(self) -> None:
        done = _packeteer(
            "stream", "--load-protocol", str(self.module),
            "--protocol", "udp", "--payload", self.name,
            "--client-ip", "10.0.0.1", "--server-ip", "10.0.0.2",
            "--pcap", str(self.dir / "o.pcap"),
        )
        self.assertEqual(done.returncode, 1)
        self.assertIn("--protocol-messages", done.stderr)

    def test_an_empty_list_is_rejected(self) -> None:
        self.messages.write_text("[]")
        done = self._stream("--pcap", str(self.dir / "o.pcap"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("non-empty JSON array", done.stderr)

    def test_a_section_that_will_not_encode_names_the_file(self) -> None:
        self.messages.write_text(json.dumps([{"owner": 5}]))
        done = self._stream("--pcap", str(self.dir / "o.pcap"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("msgs.json", done.stderr)


if __name__ == "__main__":
    unittest.main()
