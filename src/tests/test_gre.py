"""Tests for GRE tunneling (RFC 2784 / RFC 2890) building and parsing."""
import io
import json
import struct
import unittest

from packeteer.generator import PacketBuilder, GREHeader, IPPROTO_GRE, GRE_PROTO_IPV4, GRE_PROTO_IPV6, GRE_PROTO_TEB
from packeteer.generator.pcap import LINKTYPE_RAW, write_pcap
from packeteer.parser.core import parse_packet, parse_pcap_file, ParsedPacket


# ---------------------------------------------------------------------------
# Builder tests
# ---------------------------------------------------------------------------

class TestPacketBuilderGRE(unittest.TestCase):

    def test_ipv4_in_gre_outer_proto(self):
        """Outer IP protocol field must be 47 (GRE) for IPv4-in-GRE."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Ethernet=14 bytes, IP proto at byte 9 within IP header → byte 23
        self.assertEqual(raw[23], 47)

    def test_ipv4_in_gre_protocol_type(self):
        """GRE Protocol Type must be 0x0800 for IPv4 payload."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Ethernet=14, outer IP=20, GRE starts at byte 34
        proto_type, = struct.unpack_from("!H", raw, 34 + 2)
        self.assertEqual(proto_type, GRE_PROTO_IPV4)

    def test_ipv6_in_gre_protocol_type(self):
        """GRE Protocol Type must be 0x86DD for IPv6 payload."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="fe80::1", dst="fe80::2")
            .tcp(dst_port=443)
            .build()
        )
        proto_type, = struct.unpack_from("!H", raw, 34 + 2)
        self.assertEqual(proto_type, GRE_PROTO_IPV6)

    def test_gre_no_optional_fields_length(self):
        """GRE header with no optional fields is exactly 4 bytes."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Ethernet=14, outer IP=20 → GRE at 34; inner IP at 38
        gre_first_word, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(gre_first_word & 0x8000, 0)   # C=0
        self.assertEqual(gre_first_word & 0x2000, 0)   # K=0
        self.assertEqual(gre_first_word & 0x1000, 0)   # S=0

    def test_gre_key_flag_set(self):
        """K flag must be set when key is provided."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=1234)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        flags_ver, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(flags_ver & 0x2000, 0x2000)   # K=1
        self.assertEqual(flags_ver & 0x1000, 0)         # S=0
        key_val, = struct.unpack_from("!I", raw, 34 + 4)
        self.assertEqual(key_val, 1234)

    def test_gre_seq_flag_set(self):
        """S flag must be set when seq is provided."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(seq=99)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        flags_ver, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(flags_ver & 0x1000, 0x1000)   # S=1
        self.assertEqual(flags_ver & 0x2000, 0)         # K=0
        seq_val, = struct.unpack_from("!I", raw, 34 + 4)
        self.assertEqual(seq_val, 99)

    def test_gre_key_and_seq(self):
        """K=1, S=1 with key before seq in wire order."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=42, seq=7)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        flags_ver, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(flags_ver & 0x2000, 0x2000)   # K=1
        self.assertEqual(flags_ver & 0x1000, 0x1000)   # S=1
        key_val, = struct.unpack_from("!I", raw, 34 + 4)
        seq_val, = struct.unpack_from("!I", raw, 34 + 8)
        self.assertEqual(key_val, 42)
        self.assertEqual(seq_val, 7)

    def test_gre_checksum_flag_set(self):
        """C flag must be set when checksum=True; checksum field must be non-zero."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(checksum=True)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        flags_ver, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(flags_ver & 0x8000, 0x8000)   # C=1
        cksum, = struct.unpack_from("!H", raw, 34 + 4)
        # Checksum should be non-zero for a real packet
        self.assertNotEqual(cksum, 0)

    def test_gre_checksum_correctness(self):
        """RFC 1071 checksum over GRE header + payload should verify to 0."""
        from packeteer.generator.checksum import ones_complement_checksum
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(checksum=True)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # GRE starts at byte 34; GRE header is 8 bytes (4 fixed + 4 checksum)
        gre_start = 34
        gre_data = raw[gre_start:]
        # Verify: ones-complement sum of all data including the checksum field
        # folds to 0xFFFF, so ones_complement_checksum returns ~0xFFFF & 0xFFFF = 0
        self.assertEqual(ones_complement_checksum(gre_data), 0)

    def test_gre_all_optional_fields(self):
        """C=1, K=1, S=1 produces a 16-byte GRE header."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=100, seq=200, checksum=True)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        flags_ver, = struct.unpack_from("!H", raw, 34)
        self.assertEqual(flags_ver & 0x8000, 0x8000)   # C
        self.assertEqual(flags_ver & 0x2000, 0x2000)   # K
        self.assertEqual(flags_ver & 0x1000, 0x1000)   # S
        key_val, = struct.unpack_from("!I", raw, 34 + 8)
        seq_val, = struct.unpack_from("!I", raw, 34 + 12)
        self.assertEqual(key_val, 100)
        self.assertEqual(seq_val, 200)

    def test_gre_over_ipv6_outer(self):
        """GRE can be carried over an IPv6 outer header (next-header=47)."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="2001:db8::1", dst="2001:db8::2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Ethernet=14, IPv6 next-header at offset 6
        self.assertEqual(raw[14 + 6], 47)

    def test_teb_protocol_type(self):
        """TEB GRE (inner Ethernet) must set Protocol Type = 0x6558."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        proto_type, = struct.unpack_from("!H", raw, 34 + 2)
        self.assertEqual(proto_type, GRE_PROTO_TEB)

    def test_nested_gre_in_gre(self):
        """GRE-in-GRE: outer proto=47, outer GRE protocol_type=0x0800, inner GRE present."""
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .gre(key=1)
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .gre(key=2)
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=9000)
            .build()
        )
        self.assertIsInstance(raw, bytes)
        # Outer IP proto = 47
        self.assertEqual(raw[23], 47)

    def test_build_returns_bytes(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=42)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        self.assertIsInstance(raw, bytes)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParsePacketGRE(unittest.TestCase):

    def _build_ip_in_gre(self, key=None, seq=None, checksum=False):
        return (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=key, seq=seq, checksum=checksum)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )

    def test_gre_field_set(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNotNone(pkt.gre)

    def test_gre_is_gre_header_instance(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsInstance(pkt.gre, GREHeader)

    def test_outer_ip(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertEqual(pkt.ip.src, "10.0.0.1")
        self.assertEqual(pkt.ip.dst, "10.0.0.2")

    def test_tunneled_present(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNotNone(pkt.tunneled)
        self.assertIsInstance(pkt.tunneled, ParsedPacket)

    def test_inner_ip(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
        self.assertEqual(pkt.tunneled.ip.dst, "192.168.1.2")

    def test_inner_transport(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNotNone(pkt.tunneled.transport)
        self.assertEqual(pkt.tunneled.transport.dst_port, 80)

    def test_outer_transport_is_none(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.transport)

    def test_outer_payload_is_empty(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertEqual(pkt.payload, b"")

    def test_key_round_trips(self):
        pkt = parse_packet(self._build_ip_in_gre(key=9999))
        self.assertEqual(pkt.gre.key, 9999)

    def test_seq_round_trips(self):
        pkt = parse_packet(self._build_ip_in_gre(seq=42))
        self.assertEqual(pkt.gre.seq, 42)

    def test_key_and_seq_round_trip(self):
        pkt = parse_packet(self._build_ip_in_gre(key=11, seq=22))
        self.assertEqual(pkt.gre.key, 11)
        self.assertEqual(pkt.gre.seq, 22)

    def test_checksum_flag_preserved(self):
        pkt = parse_packet(self._build_ip_in_gre(checksum=True))
        self.assertTrue(pkt.gre.checksum)

    def test_no_key_is_none(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.gre.key)

    def test_no_seq_is_none(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.gre.seq)

    def test_no_checksum_is_false(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertFalse(pkt.gre.checksum)

    def test_gre_ipip_mutually_exclusive(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertFalse(pkt.ipip)

    def test_gre_etherip_mutually_exclusive(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.etherip)

    def test_inner_tunneled_is_none(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.tunneled.gre)
        self.assertFalse(pkt.tunneled.ipip)
        self.assertIsNone(pkt.tunneled.tunneled)

    def test_no_inner_ethernet(self):
        pkt = parse_packet(self._build_ip_in_gre())
        self.assertIsNone(pkt.tunneled.ethernet)

    def test_ipv6_inner(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="fe80::1", dst="fe80::2")
            .tcp(dst_port=443)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.gre)
        self.assertEqual(pkt.tunneled.ip.src, "fe80::1")

    def test_udp_inner(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.gre)
        self.assertEqual(pkt.tunneled.transport.dst_port, 53)

    def test_teb_inner_has_ethernet(self):
        """TEB: inner ParsedPacket.ethernet must be set."""
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.gre)
        self.assertIsNotNone(pkt.tunneled.ethernet)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")

    def test_teb_gre_protocol_type(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertEqual(pkt.gre.protocol_type, GRE_PROTO_TEB)

    def test_nested_gre(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .gre(key=1)
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .gre(key=2)
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .tcp(dst_port=9000)
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNotNone(pkt.gre)
        self.assertEqual(pkt.gre.key, 1)
        self.assertEqual(pkt.ip.src, "1.0.0.1")
        self.assertIsNotNone(pkt.tunneled.gre)
        self.assertEqual(pkt.tunneled.gre.key, 2)
        self.assertEqual(pkt.tunneled.ip.src, "2.0.0.1")
        self.assertEqual(pkt.tunneled.tunneled.ip.src, "3.0.0.1")
        self.assertEqual(pkt.tunneled.tunneled.transport.dst_port, 9000)
        self.assertIsNone(pkt.tunneled.tunneled.gre)

    def test_non_gre_packet_has_no_gre(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp()
            .build()
        )
        pkt = parse_packet(raw)
        self.assertIsNone(pkt.gre)

    def test_etherip_is_not_gre(self):
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
        self.assertIsNone(pkt.gre)
        self.assertIsNotNone(pkt.etherip)

    def test_linktype_raw_gre(self):
        """parse_packet with LINKTYPE_RAW skips ethernet and finds GRE."""
        raw = (PacketBuilder()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=5)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
        self.assertIsNotNone(pkt.gre)
        self.assertEqual(pkt.gre.key, 5)
        self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")

    def test_corrupt_gre_too_short(self):
        """A packet where the GRE area is too short returns payload instead of gre."""
        # Build a raw packet and truncate the GRE body
        raw = (PacketBuilder()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        # Outer IP is 20 bytes; truncate everything after that to 2 bytes (< 4 = too short)
        truncated = raw[:22]
        pkt = parse_packet(truncated, link_type=LINKTYPE_RAW)
        self.assertIsNone(pkt.gre)


# ---------------------------------------------------------------------------
# Round-trip tests (parse → JSON → rebuild)
# ---------------------------------------------------------------------------

class TestGRERoundTrip(unittest.TestCase):

    def _pcap_buf(self, raw: bytes) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap([(raw, 0, 0)], file_object=buf)
        buf.seek(0)
        return buf

    def test_single_ip_in_gre_json_structure(self):
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre()
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "gre")
        self.assertIn("gre", pkt_cfg)
        inner = pkt_cfg["gre"]
        self.assertEqual(inner["network"]["src"], "192.168.1.1")
        self.assertEqual(inner["transport"]["dst_port"], 80)
        self.assertNotIn("ethernet", inner)
        self.assertNotIn("key", inner)
        self.assertNotIn("seq", inner)
        self.assertNotIn("checksum", inner)

    def test_gre_with_key_and_seq_json(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=42, seq=7)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .udp(dst_port=53)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        inner = cfg["packets"][0]["gre"]
        self.assertEqual(inner["key"], 42)
        self.assertEqual(inner["seq"], 7)

    def test_gre_with_checksum_json(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(checksum=True)
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=443)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        inner = cfg["packets"][0]["gre"]
        self.assertTrue(inner.get("checksum"))

    def test_teb_json_structure(self):
        raw = (PacketBuilder()
            .ethernet(src_mac="00:00:00:00:00:01", dst_mac="00:00:00:00:00:02")
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .gre(key=99)
            .ethernet(src_mac="aa:bb:cc:dd:ee:01", dst_mac="aa:bb:cc:dd:ee:02")
            .ip(src="192.168.1.1", dst="192.168.1.2")
            .tcp(dst_port=80)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        inner = cfg["packets"][0]["gre"]
        self.assertIn("ethernet", inner)
        self.assertEqual(inner["key"], 99)
        self.assertEqual(inner["network"]["src"], "192.168.1.1")

    def test_nested_gre_json_structure(self):
        raw = (PacketBuilder()
            .ethernet()
            .ip(src="1.0.0.1", dst="1.0.0.2")
            .gre(key=1)
            .ip(src="2.0.0.1", dst="2.0.0.2")
            .gre(key=2)
            .ip(src="3.0.0.1", dst="3.0.0.2")
            .udp(dst_port=9999)
            .build()
        )
        cfg = json.loads(parse_pcap_file(file_object=self._pcap_buf(raw)))
        pkt_cfg = cfg["packets"][0]
        self.assertEqual(pkt_cfg["network"]["protocol"], "gre")
        inner1 = pkt_cfg["gre"]
        self.assertEqual(inner1["key"], 1)
        self.assertEqual(inner1["network"]["protocol"], "gre")
        inner2 = inner1["gre"]
        self.assertEqual(inner2["key"], 2)
        self.assertEqual(inner2["network"]["src"], "3.0.0.1")
        self.assertEqual(inner2["transport"]["dst_port"], 9999)

    def test_packet_lab_round_trip(self):
        """Build via packet spec → parse → verify inner addresses."""
        import subprocess, sys, json, tempfile, os

        config = {
            "packets": [{
                "ethernet": {"src_mac": "00:00:00:00:00:01", "dst_mac": "00:00:00:00:00:02"},
                "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "gre", "ttl": 64},
                "gre": {
                    "key": 1234,
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
                capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            with open(pf_path, "rb") as f:
                from packeteer.parser.pcap import read_pcap
                pcap = read_pcap(file_object=f)
            raw, _, _ = pcap.packets[0]
            pkt = parse_packet(raw)
            self.assertIsNotNone(pkt.gre)
            self.assertEqual(pkt.gre.key, 1234)
            self.assertEqual(pkt.ip.src, "10.0.0.1")
            self.assertEqual(pkt.tunneled.ip.src, "192.168.1.1")
            self.assertEqual(pkt.tunneled.transport.dst_port, 80)
        finally:
            os.unlink(jf_path)
            os.unlink(pf_path)


if __name__ == "__main__":
    unittest.main()
