"""Loading a user protocol from the command line (#118)."""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from packeteer import protocols
from packeteer.generate import PacketBuilder
from packeteer.pcap import write_pcap

_SPEC = """
name: sensor
version: "1.0"
over: udp
ports: [9000]
input: datagram
entry: Reading
units:
  Reading:
    fields:
      - {name: magic, type: {int: {bits: 16}}, const: 21317}
      - {name: owner, type: {string: {size: 8}}, sensitive: true}
      - {name: value, type: {int: {bits: 16}}}
"""


def _packeteer(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    """Run the CLI as a subprocess, so the registry starts empty each time."""
    return subprocess.run(
        [sys.executable, "-m", "packeteer", *args],
        capture_output=True, text=True, check=False,
        env={**os.environ, **(env or {})},
    )


class _Workspace(unittest.TestCase):
    """A compiled sensor.py and a capture carrying one of its datagrams."""

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(self._clean)
        (self.dir / "sensor.yaml").write_text(textwrap.dedent(_SPEC))
        done = _packeteer("protocol", "compile", str(self.dir / "sensor.yaml"),
                          "-o", str(self.dir / "sensor.py"))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.module = self.dir / "sensor.py"

        payload = struct.pack("!H", 21317) + b"alice   " + struct.pack("!H", 21)
        frame = (PacketBuilder()
                 .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp(src_port=5000, dst_port=9000)
                 .payload(data=payload).build())
        self.capture = self.dir / "cap.pcap"
        write_pcap([(frame, 1_700_000_000, 0)], path=str(self.capture))

    def _clean(self) -> None:
        import shutil
        shutil.rmtree(self.dir, ignore_errors=True)


class TestTheFlag(_Workspace):
    """`--load-protocol`, the explicit per-invocation route."""

    def test_without_it_the_payload_stays_opaque(self) -> None:
        """The control: the flag must be what makes the difference."""
        done = _packeteer("parse", str(self.capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("sensor", json.loads(done.stdout)["packets"][0])
        self.assertIn("payload", json.loads(done.stdout)["packets"][0])

    def test_after_the_subcommand(self) -> None:
        """Where it reads naturally, and where people will type it."""
        done = _packeteer("parse", "--load-protocol", str(self.module),
                          str(self.capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        section = json.loads(done.stdout)["packets"][0]["sensor"]
        self.assertEqual(section["owner"], "alice   ")
        self.assertEqual(section["value"], 21)

    def test_before_the_subcommand(self) -> None:
        done = _packeteer("--load-protocol", str(self.module), "parse",
                          str(self.capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("sensor", json.loads(done.stdout)["packets"][0])

    def test_a_missing_module_fails_loudly(self) -> None:
        done = _packeteer("--load-protocol", str(self.dir / "nope.py"),
                          "parse", str(self.capture))
        self.assertEqual(done.returncode, 1)
        self.assertIn("no protocol module at", done.stderr)

    def test_a_module_that_raises_names_the_file_and_the_error(self) -> None:
        broken = self.dir / "broken.py"
        broken.write_text("raise RuntimeError('boom')\n")
        done = _packeteer("--load-protocol", str(broken), "parse",
                          str(self.capture))
        self.assertEqual(done.returncode, 1)
        self.assertIn("broken.py", done.stderr)
        self.assertIn("RuntimeError", done.stderr)

    def test_a_module_registering_nothing_says_so(self) -> None:
        """Silence here is indistinguishable from a protocol that never arrived."""
        empty = self.dir / "empty.py"
        empty.write_text("x = 1\n")
        done = _packeteer("--load-protocol", str(empty), "parse",
                          str(self.capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("registered no protocol", done.stderr)


class TestTheEnvironmentVariable(_Workspace):
    """`PACKETEER_PROTOCOLS`, for a shell that always wants the same ones."""

    def test_it_loads_the_protocol(self) -> None:
        done = _packeteer("parse", str(self.capture),
                          env={"PACKETEER_PROTOCOLS": str(self.module)})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("sensor", json.loads(done.stdout)["packets"][0])

    def test_several_are_separated_by_the_path_separator(self) -> None:
        value = os.pathsep.join([str(self.module), str(self.module)])
        done = _packeteer("parse", str(self.capture),
                          env={"PACKETEER_PROTOCOLS": value})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("sensor", json.loads(done.stdout)["packets"][0])


class TestTheSpecKey(_Workspace):
    """A spec names its own protocols, so a round trip needs no flag twice."""

    def _parse_to_spec(self) -> Path:
        spec = self.dir / "spec.json"
        done = _packeteer("parse", "--load-protocol", str(self.module),
                          str(self.capture), "-o", str(spec))
        self.assertEqual(done.returncode, 0, done.stderr)
        return spec

    def test_parse_records_the_module_it_was_given(self) -> None:
        config = json.loads(self._parse_to_spec().read_text())
        self.assertEqual(config["protocols"], ["sensor.py"])

    def test_the_path_is_relative_to_the_spec_file(self) -> None:
        """So a spec and the module beside it move together."""
        config = json.loads(self._parse_to_spec().read_text())
        self.assertFalse(os.path.isabs(config["protocols"][0]))

    def test_build_reloads_it_without_the_flag(self) -> None:
        """#118's acceptance criterion, end to end."""
        spec = self._parse_to_spec()
        out = self.dir / "rebuilt.pcap"
        done = _packeteer("build", str(spec), "--pcap", str(out))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(out.read_bytes(), self.capture.read_bytes())

    def test_it_says_what_it_is_importing(self) -> None:
        """It is executing Python named in a data file; that is not silent."""
        spec = self._parse_to_spec()
        done = _packeteer("build", str(spec), "--pcap", str(self.dir / "o.pcap"))
        self.assertIn("Loading protocol module named by", done.stderr)
        self.assertIn("sensor.py", done.stderr)

    def test_sanitise_redacts_the_loaded_protocol(self) -> None:
        """#117's redaction reached through #118's loading."""
        spec = self._parse_to_spec()
        clean = self.dir / "clean.json"
        done = _packeteer("sanitise", str(spec), "-o", str(clean))
        self.assertEqual(done.returncode, 0, done.stderr)
        section = json.loads(clean.read_text())["packets"][0]["sensor"]
        self.assertEqual(section["owner"], "[redacted]")
        self.assertEqual(section["value"], 21, "and only what is annotated")

    def test_a_malformed_key_is_rejected(self) -> None:
        spec = self._parse_to_spec()
        config = json.loads(spec.read_text())
        config["protocols"] = "sensor.py"          # a string, not a list
        spec.write_text(json.dumps(config))
        done = _packeteer("build", str(spec), "--pcap", str(self.dir / "o.pcap"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("must be a list", done.stderr)


class TestLoadModule(unittest.TestCase):
    """The API underneath, which the CLI is only a caller of."""

    def test_it_returns_what_registered(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            module = Path(tmp) / "tiny.py"
            module.write_text(textwrap.dedent('''
                from packeteer.protocols import AppProtocol, register
                register(AppProtocol(
                    name="tiny", over="udp", ports=frozenset({9911}),
                    messages=(dict,),
                    decode=lambda b, t="udp": {}, encode=lambda m, t="udp": b"",
                    to_spec=lambda m: {}, from_spec=lambda s: {},
                ))
            '''))
            added = protocols.load_module(module)
            self.addCleanup(protocols.unregister, "tiny")
            self.assertEqual([p.name for p in added], ["tiny"])

    def test_a_missing_file_raises(self) -> None:
        with self.assertRaises(protocols.ProtocolError):
            protocols.load_module("/no/such/module.py")


if __name__ == "__main__":
    unittest.main()
