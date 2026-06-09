"""Unit tests for packeteer.parse.info and the `file-info` CLI command."""
from __future__ import annotations

import argparse
import json
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import PcapInfo, format_pcap_info, pcap_info
from packeteer.pcap import LINKTYPE_ETHERNET, LINKTYPE_RAW, write_pcap, write_pcapng

# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_pcap(packets: list, *, link_type: int = LINKTYPE_ETHERNET,
                pcapng: bool = False) -> str:
    suffix = ".pcapng" if pcapng else ".pcap"
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    writer = write_pcapng if pcapng else write_pcap
    writer(packets, path=path, link_type=link_type)
    return path


def _eth(src: str, dst: str, sport: int, dport: int, ts: int = 0) -> tuple:
    raw = (PacketBuilder().ethernet()
           .ip(src=src, dst=dst).tcp(src_port=sport, dst_port=dport).build())
    return (raw, ts, 0)


def _raw_ip(src: str, dst: str, sport: int, dport: int, ts: int = 0) -> tuple:
    raw = (PacketBuilder()
           .ip(src=src, dst=dst).tcp(src_port=sport, dst_port=dport).build())
    return (raw, ts, 0)


# ── Sessions ──────────────────────────────────────────────────────────────────

class TestSessions(unittest.TestCase):

    def test_directional_5tuples_counted_separately(self) -> None:
        path = _write_pcap([
            _eth("10.0.0.1", "10.0.0.2", 1111, 80),
            _eth("10.0.0.2", "10.0.0.1", 80, 1111),   # reverse direction
        ])
        info = pcap_info(path=path)
        self.assertEqual(info.session_count, 2)
        os.remove(path)

    def test_duplicate_5tuple_counted_once(self) -> None:
        path = _write_pcap([
            _eth("10.0.0.1", "10.0.0.2", 1111, 80),
            _eth("10.0.0.1", "10.0.0.2", 1111, 80),
        ])
        info = pcap_info(path=path)
        self.assertEqual(info.session_count, 1)
        self.assertEqual(info.packet_count, 2)
        os.remove(path)

    def test_distinct_sessions(self) -> None:
        path = _write_pcap([
            _eth("10.0.0.1", "10.0.0.2", 1111, 80),
            _eth("10.0.0.1", "10.0.0.2", 2222, 80),
            _eth("10.0.0.1", "10.0.0.3", 1111, 80),
        ])
        info = pcap_info(path=path)
        self.assertEqual(info.session_count, 3)
        os.remove(path)

    def test_icmp_session_without_ports(self) -> None:
        icmp = (PacketBuilder().ethernet()
                .ip(src="10.0.0.1", dst="10.0.0.2").icmp().build())
        path = _write_pcap([(icmp, 0, 0)])
        info = pcap_info(path=path)
        self.assertEqual(info.session_count, 1)
        self.assertEqual(info.layer_counts.get("icmp"), 1)
        os.remove(path)


# ── Layer statistics ──────────────────────────────────────────────────────────

class TestLayerStats(unittest.TestCase):

    def test_layer_counts(self) -> None:
        udp = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2").udp(src_port=5, dst_port=9).build())
        path = _write_pcap([
            _eth("10.0.0.1", "10.0.0.2", 1111, 80),
            _eth("10.0.0.1", "10.0.0.2", 2222, 80),
            (udp, 0, 0),
        ])
        info = pcap_info(path=path)
        self.assertEqual(info.layer_counts["ethernet"], 3)
        self.assertEqual(info.layer_counts["ipv4"], 3)
        self.assertEqual(info.layer_counts["tcp"], 2)
        self.assertEqual(info.layer_counts["udp"], 1)
        self.assertNotIn("ipv6", info.layer_counts)  # zero counts are dropped
        os.remove(path)

    def test_ipv6_layer(self) -> None:
        # raw IPv6 via the ip() builder auto-detects version from the address
        v6 = (PacketBuilder().ethernet()
              .ip(src="2001:db8::1", dst="2001:db8::2")
              .tcp(src_port=1, dst_port=2).build())
        path = _write_pcap([(v6, 0, 0)])
        info = pcap_info(path=path)
        self.assertEqual(info.layer_counts.get("ipv6"), 1)
        self.assertNotIn("ipv4", info.layer_counts)
        os.remove(path)


# ── Link-type auto-correction ─────────────────────────────────────────────────

class TestLinkTypeDetection(unittest.TestCase):

    def test_mislabeled_raw_as_ethernet_is_corrected(self) -> None:
        # raw-IP packets written with an (incorrect) Ethernet link type
        path = _write_pcap(
            [_raw_ip("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)],
            link_type=LINKTYPE_ETHERNET,
        )
        info = pcap_info(path=path)
        self.assertEqual(info.declared_link_type, LINKTYPE_ETHERNET)
        self.assertEqual(info.link_type, LINKTYPE_RAW)
        self.assertTrue(info.link_type_overridden)
        os.remove(path)

    def test_correct_ethernet_left_alone(self) -> None:
        path = _write_pcap(
            [_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)],
            link_type=LINKTYPE_ETHERNET,
        )
        info = pcap_info(path=path)
        self.assertEqual(info.link_type, LINKTYPE_ETHERNET)
        self.assertFalse(info.link_type_overridden)
        os.remove(path)

    def test_explicit_link_type_disables_detection(self) -> None:
        # mislabeled raw-as-ethernet, but caller forces ethernet -> no override
        path = _write_pcap(
            [_raw_ip("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)],
            link_type=LINKTYPE_ETHERNET,
        )
        info = pcap_info(path=path, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(info.link_type, LINKTYPE_ETHERNET)
        self.assertFalse(info.link_type_overridden)
        os.remove(path)

    def test_no_auto_link_type_trusts_header(self) -> None:
        path = _write_pcap(
            [_raw_ip("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)],
            link_type=LINKTYPE_ETHERNET,
        )
        info = pcap_info(path=path, auto_link_type=False)
        self.assertEqual(info.link_type, LINKTYPE_ETHERNET)
        self.assertFalse(info.link_type_overridden)
        os.remove(path)


# ── Metadata and edge cases ───────────────────────────────────────────────────

class TestMetadata(unittest.TestCase):

    def test_empty_file(self) -> None:
        path = _write_pcap([])
        info = pcap_info(path=path)
        self.assertEqual(info.packet_count, 0)
        self.assertEqual(info.session_count, 0)
        self.assertEqual(info.layer_counts, {})
        self.assertIsNone(info.capture_duration_s)
        os.remove(path)

    def test_duration(self) -> None:
        path = _write_pcap([
            _eth("10.0.0.1", "10.0.0.2", 1, 80, ts=100),
            _eth("10.0.0.1", "10.0.0.2", 2, 80, ts=105),
        ])
        info = pcap_info(path=path)
        self.assertAlmostEqual(info.capture_duration_s, 5.0)
        os.remove(path)

    def test_pcapng_file_type(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)], pcapng=True)
        info = pcap_info(path=path)
        self.assertEqual(info.file_type, "pcapng")
        os.remove(path)

    def test_to_dict_roundtrips_through_json(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)])
        info = pcap_info(path=path)
        data = json.loads(json.dumps(info.to_dict()))
        self.assertEqual(data["packet_count"], 1)
        self.assertEqual(data["session_count"], 1)
        os.remove(path)

    def test_requires_exactly_one_source(self) -> None:
        with self.assertRaises(ValueError):
            pcap_info()


# ── format_pcap_info ──────────────────────────────────────────────────────────

class TestFormat(unittest.TestCase):

    def test_text_report_contains_key_lines(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)])
        text = format_pcap_info(pcap_info(path=path))
        self.assertIn("Packets:", text)
        self.assertIn("Sessions:", text)
        self.assertIn("ethernet", text)
        os.remove(path)

    def test_override_note_in_report(self) -> None:
        path = _write_pcap(
            [_raw_ip("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)],
            link_type=LINKTYPE_ETHERNET,
        )
        text = format_pcap_info(pcap_info(path=path))
        self.assertIn("auto-corrected", text)
        os.remove(path)

    def test_empty_layers_render(self) -> None:
        info = PcapInfo(
            path=None, file_type="pcap",
            declared_link_type=1, link_type=1, link_type_overridden=False,
            nanoseconds=False, packet_count=0, session_count=0,
        )
        self.assertIn("(none)", format_pcap_info(info))

    def test_no_ip_note_when_no_ip_layer(self) -> None:
        info = PcapInfo(
            path=None, file_type="pcap",
            declared_link_type=1, link_type=1, link_type_overridden=False,
            nanoseconds=False, packet_count=5, session_count=0,
            layer_counts={"ethernet": 5, "payload": 5},
        )
        text = format_pcap_info(info)
        self.assertIn("no packets contained an IP layer", text)

    def test_no_ip_note_absent_for_normal_capture(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)])
        text = format_pcap_info(pcap_info(path=path))
        self.assertNotIn("no packets contained an IP layer", text)
        os.remove(path)

    def test_no_ip_note_absent_for_empty_capture(self) -> None:
        info = PcapInfo(
            path=None, file_type="pcap",
            declared_link_type=1, link_type=1, link_type_overridden=False,
            nanoseconds=False, packet_count=0, session_count=0,
        )
        self.assertNotIn("no packets contained an IP layer", format_pcap_info(info))


# ── Packet limit (num) ────────────────────────────────────────────────────────

class TestNum(unittest.TestCase):

    def test_num_caps_packet_count(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(50)])
        info = pcap_info(path=path, num=10)
        self.assertEqual(info.packet_count, 10)
        self.assertEqual(info.packet_limit, 10)
        os.remove(path)

    def test_num_larger_than_file(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(5)])
        info = pcap_info(path=path, num=100)
        self.assertEqual(info.packet_count, 5)
        os.remove(path)

    def test_num_unset_reads_all(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(8)])
        info = pcap_info(path=path)
        self.assertEqual(info.packet_count, 8)
        self.assertIsNone(info.packet_limit)
        os.remove(path)

    def test_num_detects_link_type_on_subset(self) -> None:
        # mislabeled raw-as-ethernet; only the first few packets are needed
        path = _write_pcap(
            [_raw_ip("10.0.0.1", "10.0.0.2", i % 60000, 80) for i in range(1000)],
            link_type=LINKTYPE_ETHERNET,
        )
        info = pcap_info(path=path, num=20)
        self.assertEqual(info.packet_count, 20)
        self.assertEqual(info.link_type, LINKTYPE_RAW)
        self.assertTrue(info.link_type_overridden)
        os.remove(path)

    def test_limit_note_in_report(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(50)])
        text = format_pcap_info(pcap_info(path=path, num=10))
        self.assertIn("limited to first 10", text)
        os.remove(path)

    def test_no_limit_note_when_file_smaller(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(3)])
        text = format_pcap_info(pcap_info(path=path, num=10))
        self.assertNotIn("limited to first", text)
        os.remove(path)


# ── CLI ───────────────────────────────────────────────────────────────────────

class TestCmdFileInfo(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            pcap="", json=False, link_type=None, no_auto_link_type=False, num=None,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def test_cli_text_output(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)])
        with patch("sys.stdout", new=StringIO()) as out:
            cli._cmd_file_info(self._args(pcap=path))
        self.assertIn("Sessions:", out.getvalue())
        os.remove(path)

    def test_cli_json_output(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", 1, 80)])
        with patch("sys.stdout", new=StringIO()) as out:
            cli._cmd_file_info(self._args(pcap=path, json=True))
        data = json.loads(out.getvalue())
        self.assertEqual(data["packet_count"], 1)
        os.remove(path)

    def test_cli_missing_file_exits(self) -> None:
        with patch("sys.stderr", new=StringIO()), \
                self.assertRaises(SystemExit):
            cli._cmd_file_info(self._args(pcap="/no/such/file.pcap"))

    def test_cli_num_limits_output(self) -> None:
        path = _write_pcap([_eth("10.0.0.1", "10.0.0.2", i, 80) for i in range(30)])
        with patch("sys.stdout", new=StringIO()) as out:
            cli._cmd_file_info(self._args(pcap=path, json=True, num=5))
        self.assertEqual(json.loads(out.getvalue())["packet_count"], 5)
        os.remove(path)


if __name__ == "__main__":
    unittest.main()
