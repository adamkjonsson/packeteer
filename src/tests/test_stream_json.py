"""`stream --json` is `parse`'s format, and replays with `build` (#199).

`stream --json` had a hand-written copy of `parse`'s conversion that had
drifted: it wrote a decoded application section neither as itself nor as
payload bytes, so every DNS, HTTP and compiled-protocol packet rebuilt with an
empty payload, and `build` reported success.  DNS, HTTP, DHCP and a compiled
protocol each carry a section; VPN and random bytes, which none decodes,
passed before and are here to keep passing.  Both now call
`packeteer.parse.packet_to_config`.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packeteer import protocols
from packeteer.app import register_builtins
from packeteer.generate.dhcp import DHCPMessage
from packeteer.pcap import read_pcap

_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "protocols" / "sensor.yaml"

_DNS = [
    {"id": 1, "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}]},
    {"id": 1, "qr": 1,
     "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}],
     "answers": [{"name": "www.example.com.", "rtype": 1, "rclass": 1, "ttl": 60,
                  "rdata": {"address": "93.184.216.34"}}]},
]
_SENSOR = [{"magic": 21317, "version": 1,
            "samples": [{"kind": 1, "value": "0102", "reading": 5}]}]


def _packeteer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "packeteer", *args],
                          capture_output=True, text=True, check=False)


def _frames(path: Path) -> list[bytes]:
    return [bytes(record.data) for record in read_pcap(path=str(path)).packets]


class TestStreamJSONReplays(unittest.TestCase):
    """For each payload, `stream --json` -> `build` is `stream --pcap`."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.dir = Path(tempfile.mkdtemp())
        (cls.dir / "dns.json").write_text(json.dumps(_DNS))
        (cls.dir / "sensor.json").write_text(json.dumps(_SENSOR))
        register_builtins()             # DHCP's section comes from its own to_spec
        (cls.dir / "dhcp.json").write_text(json.dumps(
            [protocols.for_section("dhcp").to_spec(DHCPMessage())]))
        done = _packeteer("protocol", "compile", str(_EXAMPLE),
                          "-o", str(cls.dir / "sensor.py"))
        assert done.returncode == 0, done.stderr
        cls.cases = {
            "dns": ["--protocol", "udp", "--payload", "dns", "--server-port", "53",
                    "--protocol-messages", str(cls.dir / "dns.json"), "--packets", "4"],
            "http": ["--payload", "http", "--requests", "2"],
            "dhcp": ["--protocol", "udp", "--payload", "dhcp", "--server-port", "67",
                     "--client-port", "68",
                     "--protocol-messages", str(cls.dir / "dhcp.json"), "--packets", "2"],
            "vpn": ["--payload", "vpn", "--packets", "4"],
            "sensor": ["--load-protocol", str(cls.dir / "sensor.py"),
                       "--protocol", "udp", "--payload", "sensor",
                       "--server-port", "9000",
                       "--protocol-messages", str(cls.dir / "sensor.json"),
                       "--packets", "3"],
            "random": ["--protocol", "udp", "--packets", "3"],
        }

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.dir, ignore_errors=True)

    def _stream(self, name: str, *out: str) -> None:
        done = _packeteer("stream", "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
                          "--seed", "5", *self.cases[name], *out)
        self.assertEqual(done.returncode, 0, done.stderr)

    def _spec(self, name: str) -> dict:
        spec = self.dir / f"{name}.json"
        self._stream(name, "--json", str(spec))
        return json.loads(spec.read_text())

    def test_build_gives_the_bytes_stream_gives(self) -> None:
        """The issue's test, one subtest per payload.

        No `--load-protocol` on `build`: for the compiled protocol, the spec's
        `protocols` key has to carry it.
        """
        for name in self.cases:
            with self.subTest(payload=name):
                pcap, built = self.dir / f"{name}.pcap", self.dir / f"{name}.built.pcap"
                self._stream(name, "--pcap", str(pcap))
                self._spec(name)
                done = _packeteer("build", str(self.dir / f"{name}.json"),
                                  "--pcap", str(built))
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertEqual(_frames(built), _frames(pcap))

    def test_a_decoded_section_is_written(self) -> None:
        sections = {"dns": "dns", "http": "http", "dhcp": "dhcp", "sensor": "sensor"}
        for name, section in sections.items():
            with self.subTest(payload=name):
                packets = self._spec(name)["packets"]
                self.assertTrue(any(section in p for p in packets),
                                [sorted(p) for p in packets])

    def test_it_is_the_format_parse_writes(self) -> None:
        """Less `packet_metadata`, `stream --json` is `parse` of the same pcap."""
        for name in ("dns", "http", "random"):
            with self.subTest(payload=name):
                pcap = self.dir / f"{name}.pcap"
                self._stream(name, "--pcap", str(pcap))
                done = _packeteer("parse", str(pcap))
                self.assertEqual(done.returncode, 0, done.stderr)
                parsed = [{k: v for k, v in p.items() if k != "packet_metadata"}
                          for p in json.loads(done.stdout)["packets"]]
                streamed = [{k: v for k, v in p.items() if k != "packet_metadata"}
                            for p in self._spec(name)["packets"]]
                self.assertEqual(streamed, parsed)

    def test_it_names_the_protocol_modules_it_was_given(self) -> None:
        """Relative to the spec, as `parse --output` writes them."""
        self.assertEqual(self._spec("sensor")["protocols"], ["sensor.py"])
        self.assertNotIn("protocols", self._spec("dns"))

    def test_its_metadata_keeps_direction_and_label(self) -> None:
        packets = self._spec("http")["packets"]
        self.assertEqual({p["packet_metadata"]["direction"] for p in packets},
                         {"c2s", "s2c"})
        self.assertEqual(packets[0]["packet_metadata"]["label"], "SYN")
