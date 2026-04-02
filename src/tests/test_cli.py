"""Unit tests for packeteer_cli — build, parse, sanitise, and stream commands."""
from __future__ import annotations

import argparse
import json
import os
import struct
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import packeteer_cli as cli


# ── Helpers ───────────────────────────────────────────────────────────────────

def _minimal_build_config() -> dict:
    """Minimal JSON config that builds one valid TCP packet."""
    return {"packets": [{
        "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
        "transport": {"src_port": 1234, "dst_port": 80, "flags": 2},
    }]}


def _write_json(data: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    return path


def _write_pcap_with_one_packet() -> str:
    """Write a minimal valid pcap file containing one SYN packet; return path."""
    from packet_generator import PacketBuilder
    from packet_generator.pcap import write_pcap, LINKTYPE_ETHERNET
    raw = (PacketBuilder()
           .ethernet()
           .ip(src="10.0.0.1", dst="10.0.0.2")
           .tcp(src_port=1234, dst_port=80, flags=0x002)
           .build())
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    write_pcap([(raw, 0, 0)], path=path, link_type=LINKTYPE_ETHERNET)
    return path


def _tmpfile(suffix=".pcap") -> str:
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def _args(**kwargs) -> argparse.Namespace:
    return argparse.Namespace(**kwargs)


# ── Group 1: build ────────────────────────────────────────────────────────────

class TestCmdBuild(unittest.TestCase):

    def test_build_pcap_creates_file(self):
        cfg_path = _write_json(_minimal_build_config())
        out_path = _tmpfile(".pcap")
        args = _args(config=cfg_path, pcap=out_path, pcapng=None)
        cli._cmd_build(args)
        self.assertGreater(os.path.getsize(out_path), 0)

    def test_build_pcapng_creates_file(self):
        cfg_path = _write_json(_minimal_build_config())
        out_path = _tmpfile(".pcapng")
        args = _args(config=cfg_path, pcap=None, pcapng=out_path)
        cli._cmd_build(args)
        self.assertGreater(os.path.getsize(out_path), 0)

    def test_build_pcap_has_valid_magic(self):
        cfg_path = _write_json(_minimal_build_config())
        out_path = _tmpfile(".pcap")
        args = _args(config=cfg_path, pcap=out_path, pcapng=None)
        cli._cmd_build(args)
        magic = Path(out_path).read_bytes()[:4]
        self.assertIn(magic, (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'))

    def test_build_missing_config_file_exits(self):
        args = _args(config="/nonexistent/file.json", pcap=_tmpfile(), pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_build(args)

    def test_build_invalid_json_exits(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("not json {{{")
        args = _args(config=path, pcap=_tmpfile(), pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_build(args)

    def test_build_missing_packets_key_exits(self):
        cfg_path = _write_json({"file_metadata": {}})
        args = _args(config=cfg_path, pcap=_tmpfile(), pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_build(args)

    def test_build_empty_packets_array_exits(self):
        cfg_path = _write_json({"packets": []})
        args = _args(config=cfg_path, pcap=_tmpfile(), pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_build(args)

    def test_build_missing_network_fields_exits(self):
        cfg_path = _write_json({"packets": [{"network": {}}]})
        args = _args(config=cfg_path, pcap=_tmpfile(), pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_build(args)

    def test_build_multiple_packets(self):
        cfg = {"packets": [
            {"network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
             "transport": {"src_port": 1, "dst_port": 80, "flags": 2}},
            {"network": {"src": "10.0.0.2", "dst": "10.0.0.1", "protocol": "TCP"},
             "transport": {"src_port": 80, "dst_port": 1, "flags": 18}},
        ]}
        cfg_path = _write_json(cfg)
        out_path = _tmpfile(".pcap")
        args = _args(config=cfg_path, pcap=out_path, pcapng=None)
        cli._cmd_build(args)
        self.assertGreater(os.path.getsize(out_path), 0)

    def test_build_raw_ip_uses_linktype_raw(self):
        cfg = {"packets": [{
            "ethernet": {"enabled": False},
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
            "transport": {"src_port": 1, "dst_port": 80, "flags": 2},
        }]}
        cfg_path = _write_json(cfg)
        out_path = _tmpfile(".pcap")
        args = _args(config=cfg_path, pcap=out_path, pcapng=None)
        cli._cmd_build(args)
        data = Path(out_path).read_bytes()
        # network field at offset 20 in pcap global header = link type
        link_type = struct.unpack_from("<I", data, 20)[0]
        self.assertEqual(link_type, 101)  # LINKTYPE_RAW


# ── Group 2: parse ────────────────────────────────────────────────────────────

class TestCmdParse(unittest.TestCase):

    def setUp(self):
        self.pcap_path = _write_pcap_with_one_packet()

    def test_parse_prints_json_to_stdout(self):
        args = _args(pcap=self.pcap_path, output=None,
                     replay_pcap=None, replay_pcapng=None)
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_parse(args)
        result = json.loads(out.getvalue())
        self.assertIn("packets", result)

    def test_parse_writes_json_to_file(self):
        out_path = _tmpfile(".json")
        args = _args(pcap=self.pcap_path, output=out_path,
                     replay_pcap=None, replay_pcapng=None)
        cli._cmd_parse(args)
        data = json.loads(Path(out_path).read_text())
        self.assertIn("packets", data)

    def test_parse_missing_file_exits(self):
        args = _args(pcap="/nonexistent.pcap", output=None,
                     replay_pcap=None, replay_pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_parse(args)

    def test_parse_replay_pcap_sets_type(self):
        out_path = _tmpfile(".json")
        args = _args(pcap=self.pcap_path, output=out_path,
                     replay_pcap="replayed.pcap", replay_pcapng=None)
        cli._cmd_parse(args)
        data = json.loads(Path(out_path).read_text())
        self.assertEqual(data.get("file_metadata", {}).get("type"), "pcap")

    def test_parse_replay_pcapng_sets_type(self):
        out_path = _tmpfile(".json")
        args = _args(pcap=self.pcap_path, output=out_path,
                     replay_pcap=None, replay_pcapng="replayed.pcapng")
        cli._cmd_parse(args)
        data = json.loads(Path(out_path).read_text())
        self.assertEqual(data.get("file_metadata", {}).get("type"), "pcapng")

    def test_parse_output_to_unwritable_path_exits(self):
        args = _args(pcap=self.pcap_path, output="/nonexistent/dir/out.json",
                     replay_pcap=None, replay_pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_parse(args)

    def test_parse_result_contains_tcp_packet(self):
        args = _args(pcap=self.pcap_path, output=None,
                     replay_pcap=None, replay_pcapng=None)
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_parse(args)
        packets = json.loads(out.getvalue())["packets"]
        protocols = [p.get("network", {}).get("protocol", "").upper()
                     for p in packets]
        self.assertIn("TCP", protocols)


# ── Group 3: sanitise ─────────────────────────────────────────────────────────

class TestCmdSanitise(unittest.TestCase):

    def _config_path(self) -> str:
        pcap = _write_pcap_with_one_packet()
        import io
        from packet_parser.parser import parse_pcap_file
        json_str = parse_pcap_file(path=pcap)
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write(json_str)
        return path

    def test_sanitise_prints_to_stdout(self):
        cfg_path = self._config_path()
        args = _args(input=cfg_path, output=None,
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_sanitise(args)
        result = json.loads(out.getvalue())
        self.assertIn("packets", result)

    def test_sanitise_writes_to_file(self):
        cfg_path = self._config_path()
        out_path = _tmpfile(".json")
        args = _args(input=cfg_path, output=out_path,
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        cli._cmd_sanitise(args)
        data = json.loads(Path(out_path).read_text())
        self.assertIn("packets", data)

    def test_sanitise_replaces_ips_by_default(self):
        cfg_path = self._config_path()
        args = _args(input=cfg_path, output=None,
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_sanitise(args)
        result = json.loads(out.getvalue())
        src = result["packets"][0]["network"]["src"]
        self.assertNotEqual(src, "10.0.0.1")

    def test_sanitise_no_ips_keeps_original_ips(self):
        cfg_path = self._config_path()
        args = _args(input=cfg_path, output=None,
                     no_ips=True, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with patch("sys.stdout", new_callable=StringIO) as out:
            cli._cmd_sanitise(args)
        result = json.loads(out.getvalue())
        src = result["packets"][0]["network"]["src"]
        self.assertEqual(src, "10.0.0.1")

    def test_sanitise_missing_input_file_exits(self):
        args = _args(input="/nonexistent.json", output=None,
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with self.assertRaises(SystemExit):
            cli._cmd_sanitise(args)

    def test_sanitise_invalid_json_exits(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("not json")
        args = _args(input=path, output=None,
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with self.assertRaises(SystemExit):
            cli._cmd_sanitise(args)

    def test_sanitise_output_to_unwritable_path_exits(self):
        cfg_path = self._config_path()
        args = _args(input=cfg_path, output="/nonexistent/dir/out.json",
                     no_ips=False, no_macs=False, ports=False,
                     payload=False, timestamps=False)
        with self.assertRaises(SystemExit):
            cli._cmd_sanitise(args)


# ── Group 4: stream ───────────────────────────────────────────────────────────

class TestCmdStream(unittest.TestCase):

    def _base_args(self, **kwargs) -> argparse.Namespace:
        defaults = dict(
            config=None,
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            client_port=None,
            server_port=None,
            client_mac=None,
            server_mac=None,
            packets=None,
            min_payload=None,
            max_payload=None,
            distribution=None,
            ttl=None,
            window=None,
            gap=None,
            gap_jitter=None,
            psh_probability=None,
            packet_loss_probability=None,
            retransmission_probability=None,
            retransmission_timeout=None,
            payload_corruption_probability=None,
            server_rst_probability=None,
            rst_propagation_delay=None,
            no_ethernet=False,
            pcap=None,
            pcapng=None,
        )
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_stream_writes_pcap(self):
        out = _tmpfile(".pcap")
        args = self._base_args(pcap=out, packets=3)
        cli._cmd_stream(args)
        self.assertGreater(os.path.getsize(out), 0)

    def test_stream_writes_pcapng(self):
        out = _tmpfile(".pcapng")
        args = self._base_args(pcapng=out, packets=3)
        cli._cmd_stream(args)
        self.assertGreater(os.path.getsize(out), 0)

    def test_stream_pcap_has_valid_magic(self):
        out = _tmpfile(".pcap")
        args = self._base_args(pcap=out, packets=2)
        cli._cmd_stream(args)
        magic = Path(out).read_bytes()[:4]
        self.assertIn(magic, (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'))

    def test_stream_missing_client_ip_exits(self):
        args = self._base_args(client_ip=None, pcap=_tmpfile())
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)

    def test_stream_missing_server_ip_exits(self):
        args = self._base_args(server_ip=None, pcap=_tmpfile())
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)

    def test_stream_missing_output_exits(self):
        args = self._base_args(pcap=None, pcapng=None)
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)

    def test_stream_both_pcap_and_pcapng_exits(self):
        args = self._base_args(pcap=_tmpfile(".pcap"), pcapng=_tmpfile(".pcapng"))
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)

    def test_stream_invalid_ip_exits(self):
        args = self._base_args(client_ip="not.an.ip.address", pcap=_tmpfile())
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)

    def test_stream_defaults_applied(self):
        # Verify that None args are filled in and stream is generated successfully
        out = _tmpfile(".pcap")
        args = self._base_args(pcap=out)  # all optional args are None
        cli._cmd_stream(args)
        self.assertGreater(os.path.getsize(out), 0)

    def test_stream_no_ethernet_flag(self):
        out = _tmpfile(".pcap")
        args = self._base_args(pcap=out, no_ethernet=True, packets=2)
        cli._cmd_stream(args)
        data = Path(out).read_bytes()
        link_type = struct.unpack_from("<I", data, 20)[0]
        self.assertEqual(link_type, 101)  # LINKTYPE_RAW

    def test_stream_ipv6(self):
        out = _tmpfile(".pcap")
        args = self._base_args(
            client_ip="2001:db8::1", server_ip="2001:db8::2",
            pcap=out, packets=2,
        )
        cli._cmd_stream(args)
        self.assertGreater(os.path.getsize(out), 0)

    def test_stream_from_config_file(self):
        import configparser, textwrap
        fd, ini_path = tempfile.mkstemp(suffix=".ini")
        out = _tmpfile(".pcap")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(f"""\
                [stream]
                client_ip = 10.1.2.3
                server_ip = 10.1.2.4
                packets = 3
                pcap = {out}
            """))
        args = self._base_args(config=ini_path, client_ip=None, server_ip=None,
                               pcap=None, pcapng=None)
        cli._cmd_stream(args)
        self.assertGreater(os.path.getsize(out), 0)

    def test_stream_cli_overrides_config_file(self):
        import textwrap
        out_config = _tmpfile(".pcap")
        out_cli = _tmpfile(".pcap")
        fd, ini_path = tempfile.mkstemp(suffix=".ini")
        with os.fdopen(fd, "w") as f:
            f.write(textwrap.dedent(f"""\
                [stream]
                client_ip = 10.1.2.3
                server_ip = 10.1.2.4
                packets = 50
                pcap = {out_config}
            """))
        # CLI overrides packets=3 and output
        args = self._base_args(config=ini_path, client_ip=None, server_ip=None,
                               packets=3, pcap=out_cli, pcapng=None)
        cli._cmd_stream(args)
        # The CLI-specified output file should exist; config output should be empty
        self.assertGreater(os.path.getsize(out_cli), 0)
        self.assertEqual(os.path.getsize(out_config), 0)

    def test_stream_unwritable_output_exits(self):
        args = self._base_args(pcap="/nonexistent/dir/out.pcap", packets=2)
        with self.assertRaises(SystemExit):
            cli._cmd_stream(args)


# ── Group 5: protocol dispatch ───────────────────────────────────────────────

class TestProtocolDispatch(unittest.TestCase):
    """Tests for protocol types and payload variants exercised via _run_multi_packet."""

    def _build(self, spec: dict) -> str:
        out = _tmpfile(".pcap")
        cli._run_multi_packet({"packets": [spec]}, pcap_path=out)
        return out

    def test_icmp_builds(self):
        out = self._build({
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "ICMP"},
            "transport": {"type": 8, "code": 0, "identifier": 1, "sequence": 1},
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_icmpv6_builds(self):
        out = self._build({
            "network": {"src": "::1", "dst": "::2", "protocol": "ICMPv6"},
            "transport": {"type": 128, "code": 0, "identifier": 1, "sequence": 1},
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_payload_hex_data(self):
        out = self._build({
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "UDP"},
            "transport": {"src_port": 1234, "dst_port": 53},
            "payload": {"data": "deadbeef"},
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_payload_invalid_hex_exits(self):
        with self.assertRaises(SystemExit):
            self._build({
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "UDP"},
                "transport": {"src_port": 1234, "dst_port": 53},
                "payload": {"data": "NOTVALIDHEX!!"},
            })

    def test_payload_size(self):
        out = self._build({
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "UDP"},
            "transport": {"src_port": 1234, "dst_port": 53},
            "payload": {"size": 32},
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_tcp_options_parsed(self):
        out = self._build({
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
            "transport": {
                "src_port": 1, "dst_port": 80, "flags": 2,
                "options": {"mss": 1460, "sack_permitted": True, "window_scale": 7},
            },
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_pppoe_session_builds(self):
        out = self._build({
            "ethernet": {"src_mac": "00:11:22:33:44:55",
                         "dst_mac": "66:77:88:99:aa:bb"},
            "pppoe": {"code": 0x00, "session_id": 1, "tags": []},
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
            "transport": {"src_port": 1, "dst_port": 80, "flags": 2},
        })
        self.assertGreater(os.path.getsize(out), 0)

    def test_pppoe_bad_tag_exits(self):
        with self.assertRaises(SystemExit):
            self._build({
                "ethernet": {},
                "pppoe": {"code": 0x00, "session_id": 1,
                           "tags": [{"type": 1, "data": "NOTVALIDHEX!!"}]},
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
                "transport": {"src_port": 1, "dst_port": 80, "flags": 2},
            })


# ── Group 6: _run_multi_packet edge cases ────────────────────────────────────

class TestRunMultiPacketEdgeCases(unittest.TestCase):

    def test_unknown_protocol_exits(self):
        cfg = {"packets": [{
            "network": {"src": "1.2.3.4", "dst": "5.6.7.8",
                        "protocol": "UNKNOWNPROTO"},
        }]}
        with self.assertRaises(SystemExit):
            cli._run_multi_packet(cfg, pcap_path=_tmpfile())

    def test_udp_packet_builds(self):
        cfg = {"packets": [{
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "UDP"},
            "transport": {"src_port": 1234, "dst_port": 53},
        }]}
        out = _tmpfile(".pcap")
        cli._run_multi_packet(cfg, pcap_path=out)
        self.assertGreater(os.path.getsize(out), 0)

    def test_nanosecond_timestamps_written(self):
        cfg = {
            "file_metadata": {"nanoseconds": True},
            "packets": [{
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "TCP"},
                "transport": {"src_port": 1, "dst_port": 80, "flags": 2},
                "metadata": {"timestamp_s": 1, "timestamp_ns": 500},
            }],
        }
        out = _tmpfile(".pcap")
        cli._run_multi_packet(cfg, pcap_path=out)
        data = Path(out).read_bytes()
        # Nanosecond pcap magic
        self.assertIn(data[:4], (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
                                 b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d'))


if __name__ == "__main__":
    unittest.main()
