"""Tests for IP-in-IP tunneling (RFC 2003 / RFC 4213) building and parsing."""
from __future__ import annotations

import io
import json
import unittest

from packeteer.generate import PacketBuilder
from packeteer.parse.core import ParsedPacket, parse_packet, parse_pcap_file
from packeteer.pcap import LINKTYPE_RAW, write_pcap

# ---------------------------------------------------------------------------
# Builder tests
# ---------------------------------------------------------------------------

class TestPacketBuilderIPIP(unittest.TestCase):
    def test_ipv4_in_ipv4_outer_proto(self):
        """Outer IP protocol field must be 4 (IPIP) for IPv4-in-IPv4."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # outer IP proto at byte 14 (eth) + 9 (offset in IP hdr) = 23
        self.assertEqual(raw[23], 4)

    def test_ipv6_in_ipv4_outer_proto(self):
        """Outer IPv4 protocol field must be 41 for IPv6-in-IPv4."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="fe80::1", dst="fe80::2")
            .tcp(dst_port=443)
            .build()
        )
        self.assertEqual(raw[23], 41)

    def test_ipv4_in_ipv6_outer_next_header(self):
        """Outer IPv6 next-header must be 4 for IPv4-in-IPv6."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Ethernet=14, IPv6 next-header at offset 6 within the IPv6 header
        self.assertEqual(raw[14 + 6], 4)

    def test_inner_ip_addresses_preserved(self):
        """Inner IP src/dst must survive the tunnel."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.ip.dst, "192.168.1.2")

    def test_double_nested_ipip(self):
        """Three levels of IP stack (IP-in-IP-in-IP) should build without error."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=9000)
            .build()
        )
        self.assertIsInstance(raw, bytes)
        # Outer IP proto = 4
        self.assertEqual(raw[23], 4)

    def test_build_returns_bytes(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        self.assertIsInstance(raw, bytes)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParsePacketIPIP(unittest.TestCase):
    def _build_single_tunnel(self) -> bytes:
        return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_ipip_flag_set(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertTrue(pkt.ipip)

    def test_outer_ip(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertEqual(pkt.ip.src, "10.0.0.1")
        self.assertEqual(pkt.ip.dst, "10.0.0.2")

    def test_tunneled_present(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertIsNotNone(pkt.tunneled)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)

    def test_inner_ip(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.ip.dst, "192.168.1.2")

    def test_inner_transport(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertIsNotNone(pkt.tunneled.transport)
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_outer_transport_is_none(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertIsNone(pkt.transport)

    def test_outer_payload_is_empty(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertEqual(pkt.payload, b"")

    def test_inner_tunneled_is_none(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertFalse(pkt.tunneled.ipip)
        self.assertIsNone(pkt.tunneled.tunneled)

    def test_no_inner_ethernet(self):
        pkt = parse_packet(self._build_single_tunnel())
        self.assertIsNone(pkt.tunneled.ethernet)

    def test_etherip_is_none(self):
        """Ipip and etherip are mutually exclusive."""
        pkt = parse_packet(self._build_single_tunnel())
        self.assertIsNone(pkt.etherip)

    def test_double_nested(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=9000)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.ip.src, "1.0.0.1")
        self.assertTrue(pkt.tunneled.ipip)
        self.assertEqual(pkt.tunneled.ip.src, "2.0.0.1")
        self.assertEqual(pkt.tunneled.tunneled.ip.src, "3.0.0.1")
        self.assertEqual(pkt.tunneled.tunneled.transport.dst_port, 9000)
        self.assertFalse(pkt.tunneled.tunneled.ipip)

    def test_non_ipip_packet_has_no_ipip(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp()
            .build()
        )
        pkt = parse_packet(raw)
        self.assertFalse(pkt.ipip)
        self.assertIsNone(pkt.tunneled)

    def test_ipv6_inner(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="fe80::1", dst="fe80::2")
            .tcp(dst_port=443)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.tunneled.ip.src, "fe80::1")

    def test_udp_inner(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.tunneled.transport.dst_port, 53)

    def test_etherip_and_ipip_mutually_exclusive(self):
        """A plain EtherIP packet must not set ipip=True."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .etherip()
            .ethernet()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertFalse(pkt.ipip)
        self.assertIsNotNone(pkt.etherip)

    def test_linktype_raw(self):
        """parse_packet with LINKTYPE_RAW skips ethernet and finds IP-in-IP."""
        raw = (PacketBuilder()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
        self.assertTrue(pkt.ipip)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")


# ---------------------------------------------------------------------------
# Round-trip tests (parse → JSON → rebuild)
# ---------------------------------------------------------------------------

class TestIPIPRoundTrip(unittest.TestCase):
    def _pcap_buf(self, raw: bytes) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        return buf

    def test_single_tunnel_json_structure(self):
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "ipip")
        self.assertIn("ipip", pkt_cfg)
        inner = pkt_cfg["ipip"]
        self.assertEqual(inner["network"]["src"], "192.168.1.1")
        self.assertEqual(inner["transport"]["dst_port"], 80)
        self.assertNotIn("ethernet", inner)

    def test_double_nested_json_structure(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .udp(dst_port=9999)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "ipip")
        inner1 = pkt_cfg["ipip"]
        self.assertEqual(inner1["network"]["protocol"], "ipip")
        inner2 = inner1["ipip"]
        self.assertEqual(inner2["network"]["src"], "3.0.0.1")
        self.assertEqual(inner2["transport"]["dst_port"], 9999)

    def test_packet_lab_round_trip(self):
        """Build via packet spec → parse → verify inner addresses."""
        import json
        import os
        import subprocess
        import sys
        import tempfile

        config = {
            "packets": [{
                "ethernet": {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"},
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "ipip", "ttl": 64},
                "ipip": {
                    "network": {"src": "192.168.1.1", "dst": "192.168.1.2",
                                "protocol": "tcp", "ttl": 64},
                    "transport": {"src_port": 12345, "dst_port": 80},
                },
                "packet_metadata": {"timestamp_s": 0, "timestamp_us": 0},
            }]
        }
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as jf:
            json.dump(config, jf)
            jf_path = jf.name
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as pf:
            pf_path = pf.name
        try:
            packet_lab = os.path.join(os.path.dirname(__file__), "..", "packeteer/__main__.py")
            result = subprocess.run(
                [sys.executable, packet_lab, "build", jf_path, "--pcap", pf_path],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            with open(pf_path, "rb") as f:
                from packeteer.pcap import read_pcap
                pcap = read_pcap(file_object=f)
            raw, _, _ = pcap.packets[0]
            pkt = parse_packet(raw)
            self.assertTrue(pkt.ipip)
            self.assertEqual(pkt.ip.src, "10.0.0.1")
            self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
            self.assertEqual(pkt.tunneled.transport.dst_port, 80)
        finally:
            os.unlink(jf_path)
            os.unlink(pf_path)


if __name__ == "__main__":
    unittest.main()
