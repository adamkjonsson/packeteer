"""A seeded stream reproduces as a file, timestamps included (#202).

`--seed` fixed the packets, but every generator took its start from the
clock, which the CLI had no way to set, so two runs of the same seeded
command wrote different files.  `--start-time` sets the start on every
path, and a seeded run without it starts at a fixed time.
"""
from __future__ import annotations

import argparse
import os
import tempfile
import time
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.pcap import read_pcap

#: Every path `stream` builds a capture on.
_PATHS: dict[str, dict[str, object]] = {
    "tcp": {},
    "udp": {"protocol": "udp"},
    "sctp": {"protocol": "sctp"},
    "sessions": {"sessions": 3},
    "http": {"payload": "http", "requests": 2},
    "vpn": {"payload": "vpn", "vpn_epochs": 1},
}


class TestStartTime(unittest.TestCase):

    def _write(self, **over: object) -> Path:
        fd, out = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        self.addCleanup(os.remove, out)
        args = argparse.Namespace(
            config=None, client_ip="10.0.0.2", server_ip="10.1.0.1",
            pcap=out, pcapng=None, json=None, payload=None, packets=3,
        )
        for key, value in over.items():
            setattr(args, key, value)
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(args)
        return Path(out)

    def _first_second(self, path: Path) -> int:
        return read_pcap(path=path).packets[0][1]

    def test_a_seeded_run_reproduces_as_a_file_on_every_path(self) -> None:
        for name, over in _PATHS.items():
            with self.subTest(path=name):
                first = self._write(seed=7, **over).read_bytes()
                second = self._write(seed=7, **over).read_bytes()
                self.assertEqual(first, second)

    def test_a_seeded_run_starts_at_the_fixed_time(self) -> None:
        for name, over in _PATHS.items():
            with self.subTest(path=name):
                second = self._first_second(self._write(seed=7, **over))
                self.assertGreaterEqual(second, int(cli._SEEDED_START_TIME))
                self.assertLess(second, int(cli._SEEDED_START_TIME) + 60)

    def test_start_time_sets_the_start_on_every_path(self) -> None:
        for name, over in _PATHS.items():
            with self.subTest(path=name):
                second = self._first_second(self._write(start_time=1000.0, **over))
                self.assertGreaterEqual(second, 1000)
                self.assertLess(second, 1060)

    def test_start_time_wins_over_the_seeded_default(self) -> None:
        second = self._first_second(self._write(seed=7, start_time=1000.0))
        self.assertLess(second, 1060)

    def test_an_unseeded_run_starts_now(self) -> None:
        second = self._first_second(self._write())
        self.assertLess(abs(second - time.time()), 60)

    def test_the_config_file_key(self) -> None:
        fd, ini = tempfile.mkstemp(suffix=".ini")
        os.close(fd)
        self.addCleanup(os.remove, ini)
        Path(ini).write_text("[stream]\nstart_time = 2000\n")
        second = self._first_second(self._write(config=ini))
        self.assertGreaterEqual(second, 2000)
        self.assertLess(second, 2060)


if __name__ == "__main__":
    unittest.main()
