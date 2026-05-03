"""Tests for packeteer_cli stream config-file support."""
from __future__ import annotations

import argparse
import textwrap
import unittest
from io import StringIO
from unittest.mock import patch

# Import the helpers directly
from packeteer.__main__ import (
    _STREAM_PARAMS,
    _apply_stream_defaults,
    _load_stream_config,
)


def _args(**kwargs: object) -> argparse.Namespace:
    """Return a Namespace with all stream attrs set to None, then override with kwargs."""
    base = {dest: None for dest, _, _ in _STREAM_PARAMS.values()}
    base["config"] = None
    base["no_ethernet"] = False
    base.update(kwargs)
    return argparse.Namespace(**base)


def _write_ini(tmp_path: object, content: str) -> str:
    """Write *content* to a temp file and return its path."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".ini")
    with os.fdopen(fd, "w") as f:
        f.write(textwrap.dedent(content))
    return path


class TestLoadStreamConfig(unittest.TestCase):

    def test_basic_values_parsed(self):
        path = _write_ini(None, """\
            [stream]
            client_ip = 192.168.1.1
            server_ip = 192.168.1.2
            packets = 20
            gap = 0.005
        """)
        cfg = _load_stream_config(path)
        self.assertEqual(cfg["client_ip"], "192.168.1.1")
        self.assertEqual(cfg["server_ip"], "192.168.1.2")
        self.assertEqual(cfg["packets"], 20)
        self.assertAlmostEqual(cfg["gap"], 0.005)

    def test_packet_loss_maps_to_packet_loss_probability(self):
        path = _write_ini(None, """\
            [stream]
            packet_loss = 0.1
        """)
        cfg = _load_stream_config(path)
        self.assertIn("packet_loss_probability", cfg)
        self.assertAlmostEqual(cfg["packet_loss_probability"], 0.1)

    def test_no_ethernet_boolean_true(self):
        for val in ("true", "yes", "1", "True", "YES"):
            with self.subTest(val=val):
                path = _write_ini(None, f"[stream]\nno_ethernet = {val}\n")
                cfg = _load_stream_config(path)
                self.assertTrue(cfg["no_ethernet"])

    def test_no_ethernet_boolean_false(self):
        path = _write_ini(None, "[stream]\nno_ethernet = false\n")
        cfg = _load_stream_config(path)
        self.assertFalse(cfg["no_ethernet"])

    def test_unknown_key_warns_and_is_ignored(self):
        path = _write_ini(None, "[stream]\nfoo_bar = baz\n")
        with patch("sys.stderr", new_callable=StringIO) as err:
            cfg = _load_stream_config(path)
        self.assertIn("unknown key", err.getvalue())
        self.assertNotIn("foo_bar", cfg)

    def test_missing_stream_section_exits(self):
        path = _write_ini(None, "[other]\nfoo = bar\n")
        with self.assertRaises(SystemExit):
            _load_stream_config(path)

    def test_file_not_found_exits(self):
        with self.assertRaises(SystemExit):
            _load_stream_config("/nonexistent/path/stream.ini")

    def test_bad_int_value_exits(self):
        path = _write_ini(None, "[stream]\npackets = not_a_number\n")
        with self.assertRaises(SystemExit):
            _load_stream_config(path)

    def test_bad_float_value_exits(self):
        path = _write_ini(None, "[stream]\ngap = abc\n")
        with self.assertRaises(SystemExit):
            _load_stream_config(path)


class TestApplyStreamDefaults(unittest.TestCase):

    def test_builtin_defaults_applied_when_all_none(self):
        args = _args()
        _apply_stream_defaults(args)
        self.assertEqual(args.client_port, 54321)
        self.assertEqual(args.server_port, 80)
        self.assertEqual(args.packets, 10)
        self.assertAlmostEqual(args.gap, 0.001)
        self.assertEqual(args.distribution, "uniform")

    def test_cli_value_takes_precedence_over_default(self):
        args = _args(packets=99)
        _apply_stream_defaults(args)
        self.assertEqual(args.packets, 99)

    def test_config_file_fills_missing_values(self):
        path = _write_ini(None, """\
            [stream]
            client_ip = 10.1.1.1
            server_ip = 10.1.1.2
            packets = 50
        """)
        args = _args(config=path)
        _apply_stream_defaults(args)
        self.assertEqual(args.client_ip, "10.1.1.1")
        self.assertEqual(args.packets, 50)

    def test_cli_takes_precedence_over_config(self):
        path = _write_ini(None, "[stream]\npackets = 50\n")
        # CLI explicitly set packets=7
        args = _args(config=path, packets=7)
        _apply_stream_defaults(args)
        self.assertEqual(args.packets, 7)

    def test_config_takes_precedence_over_builtin_default(self):
        path = _write_ini(None, "[stream]\npackets = 42\n")
        args = _args(config=path)
        _apply_stream_defaults(args)
        self.assertEqual(args.packets, 42)

    def test_builtin_default_fills_value_absent_from_config(self):
        path = _write_ini(None, "[stream]\nclient_ip = 1.2.3.4\n")
        args = _args(config=path)
        _apply_stream_defaults(args)
        # packets not in config → falls back to built-in default
        self.assertEqual(args.packets, 10)


if __name__ == "__main__":
    unittest.main()
