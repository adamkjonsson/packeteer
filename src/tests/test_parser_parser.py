from __future__ import annotations

import io
import unittest
import warnings

from packeteer.generate import PacketBuilder
from packeteer.generate.ethernet import EthernetHeader
from packeteer.generate.icmp import ICMPHeader
from packeteer.generate.icmpv6 import ICMPv6Header
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.generate.tcp import TCP_ACK, TCP_SYN, TCPHeader
from packeteer.generate.udp import UDPHeader
from packeteer.parse.core import (
    ParsedPacket,
    UnsupportedIPProtocolWarning,
    parse_packet,
    parse_pcap_file,
    parse_pcap_packet,
)
from packeteer.pcap import LINKTYPE_RAW, read_pcap, write_pcap


def _tcp(
    src_port: int = 12345, dst_port: int = 80, seq: int = 0,
    flags: int = TCP_ACK, window: int = 65535,
) -> bytes:
    return (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(src_port=src_port, dst_port=dst_port, seq=seq, flags=flags, window=window)
            .build())

def _udp(src_port: int = 12345, dst_port: int = 80) -> bytes:
    return (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .udp(src_port=src_port, dst_port=dst_port)
            .build())

def _icmp(identifier: int = 1, sequence: int = 1) -> bytes:
    return (PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .icmp(identifier=identifier, sequence=sequence)
            .build())

def _tcp6(src_port: int = 12345, dst_port: int = 80) -> bytes:
    return (PacketBuilder()
            .ethernet()
            .ip(src="::1", dst="::2")
            .tcp(src_port=src_port, dst_port=dst_port)
            .build())

def _icmpv6(identifier: int = 1, sequence: int = 1) -> bytes:
    return (PacketBuilder()
            .ethernet()
            .ip(src="::1", dst="::2")
            .icmpv6(identifier=identifier, sequence=sequence)
            .build())


class TestParsedPacketDefaults(unittest.TestCase):
    def test_all_none_by_default(self):
        pkt = ParsedPacket()
        self.assertIsNone(pkt.ethernet)
        self.assertIsNone(pkt.ip)
        self.assertIsNone(pkt.transport)
        self.assertEqual(pkt.payload, b"")


class TestParsePacketEthernetIPv4TCP(unittest.TestCase):
    def setUp(self):
        self.raw = _tcp(src_port=1234, dst_port=443, seq=999,
                        flags=TCP_SYN, window=4096)
        self.pkt = parse_packet(self.raw)

    def test_ethernet_present(self):
        self.assertIsInstance(self.pkt.ethernet, EthernetHeader)

    def test_ip_is_ipv4(self):
        self.assertIsInstance(self.pkt.ip, IPHeader)

    def test_ip_addresses(self):
        self.assertEqual(self.pkt.ip.src, "10.0.0.1")
        self.assertEqual(self.pkt.ip.dst, "10.0.0.2")

    def test_transport_is_tcp(self):
        self.assertIsInstance(self.pkt.transport, TCPHeader)

    def test_tcp_ports(self):
        self.assertEqual(self.pkt.transport.src_port, 1234)
        self.assertEqual(self.pkt.transport.dst_port, 443)

    def test_tcp_seq(self):
        self.assertEqual(self.pkt.transport.seq, 999)

    def test_tcp_flags(self):
        self.assertEqual(self.pkt.transport.flags, TCP_SYN)

    def test_tcp_window(self):
        self.assertEqual(self.pkt.transport.window, 4096)


class TestParsePacketEthernetIPv4UDP(unittest.TestCase):
    def setUp(self):
        self.pkt = parse_packet(_udp(src_port=5000, dst_port=53))

    def test_transport_is_udp(self):
        self.assertIsInstance(self.pkt.transport, UDPHeader)

    def test_udp_ports(self):
        self.assertEqual(self.pkt.transport.src_port, 5000)
        self.assertEqual(self.pkt.transport.dst_port, 53)

    def test_ip_present(self):
        self.assertIsInstance(self.pkt.ip, IPHeader)


class TestParsePacketEthernetIPv4ICMP(unittest.TestCase):
    def setUp(self):
        self.pkt = parse_packet(_icmp(identifier=7, sequence=3))

    def test_transport_is_icmp(self):
        self.assertIsInstance(self.pkt.transport, ICMPHeader)

    def test_icmp_fields(self):
        self.assertEqual(self.pkt.transport.identifier, 7)
        self.assertEqual(self.pkt.transport.sequence, 3)

    def test_ip_present(self):
        self.assertIsInstance(self.pkt.ip, IPHeader)


class TestParsePacketEthernetIPv6TCP(unittest.TestCase):
    def setUp(self):
        self.pkt = parse_packet(_tcp6(src_port=9000, dst_port=80))

    def test_ip_is_ipv6(self):
        self.assertIsInstance(self.pkt.ip, IPv6Header)

    def test_ip_addresses(self):
        self.assertEqual(self.pkt.ip.src, "::1")
        self.assertEqual(self.pkt.ip.dst, "::2")

    def test_transport_is_tcp(self):
        self.assertIsInstance(self.pkt.transport, TCPHeader)

    def test_tcp_ports(self):
        self.assertEqual(self.pkt.transport.src_port, 9000)
        self.assertEqual(self.pkt.transport.dst_port, 80)


class TestParsePacketEthernetIPv6ICMPv6(unittest.TestCase):
    def setUp(self):
        self.pkt = parse_packet(_icmpv6(identifier=4, sequence=9))

    def test_ip_is_ipv6(self):
        self.assertIsInstance(self.pkt.ip, IPv6Header)

    def test_transport_is_icmpv6(self):
        self.assertIsInstance(self.pkt.transport, ICMPv6Header)

    def test_icmpv6_fields(self):
        self.assertEqual(self.pkt.transport.identifier, 4)
        self.assertEqual(self.pkt.transport.sequence, 9)


class TestParsePacketVLAN(unittest.TestCase):
    def setUp(self):
        self.pkt = parse_packet(
            PacketBuilder().ethernet().vlan(vid=42, pcp=5)
            .ip(src="10.0.0.1", dst="10.0.0.2").udp().build()
        )

    def test_ethernet_has_vlan_tag(self):
        self.assertIsNotNone(self.pkt.ethernet.vlan_tag)

    def test_vlan_id(self):
        self.assertEqual(self.pkt.ethernet.vlan_tag.vid, 42)

    def test_vlan_pcp(self):
        self.assertEqual(self.pkt.ethernet.vlan_tag.pcp, 5)

    def test_ip_still_parsed(self):
        self.assertIsInstance(self.pkt.ip, IPHeader)

    def test_transport_still_parsed(self):
        self.assertIsInstance(self.pkt.transport, UDPHeader)


class TestParsePacketRawIP(unittest.TestCase):
    def setUp(self):
        raw_full = _tcp(src_port=1111, dst_port=2222)
        # Strip the 14-byte Ethernet header to get a raw IP packet
        self.raw_ip = raw_full[14:]
        self.pkt = parse_packet(self.raw_ip, link_type=LINKTYPE_RAW)

    def test_no_ethernet(self):
        self.assertIsNone(self.pkt.ethernet)

    def test_ip_parsed(self):
        self.assertIsInstance(self.pkt.ip, IPHeader)

    def test_transport_parsed(self):
        self.assertIsInstance(self.pkt.transport, TCPHeader)
        self.assertEqual(self.pkt.transport.src_port, 1111)
        self.assertEqual(self.pkt.transport.dst_port, 2222)


class TestParsePacketPayload(unittest.TestCase):
    def test_payload_captured(self):
        # Use ≥ 18 bytes to avoid Ethernet minimum-frame zero-padding
        payload = b"\xca\xfe\xba\xbe" * 5
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp().payload(data=payload).build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.payload, payload)

    def test_zero_payload_tcp_has_only_padding(self):
        # 14 (eth) + 20 (ip) + 20 (tcp) = 54 bytes; no padding with pad=False default.
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp().build())
        pkt = parse_packet(raw)
        self.assertEqual(pkt.payload, bytes(len(pkt.payload)))


class TestParsePacketFailures(unittest.TestCase):
    def test_empty_bytes_returns_empty_packet(self):
        pkt = parse_packet(b"")
        self.assertIsNone(pkt.ethernet)
        self.assertIsNone(pkt.ip)
        self.assertIsNone(pkt.transport)

    def test_truncated_ethernet_returns_empty_packet(self):
        pkt = parse_packet(b"\x00" * 10)
        self.assertIsNone(pkt.ethernet)
        self.assertIsNone(pkt.ip)

    def test_unknown_link_type_returns_empty_ip_and_transport(self):
        raw = _tcp()
        pkt = parse_packet(raw, link_type=999)
        self.assertIsNone(pkt.ethernet)
        self.assertIsNone(pkt.ip)
        self.assertIsNone(pkt.transport)

    def test_non_ip_ethertype_stops_after_ethernet(self):
        # ARP EtherType (0x0806) — not IPv4 or IPv6
        arp_frame = (
            b"\xaa\xbb\xcc\xdd\xee\xff"   # dst MAC
            b"\x11\x22\x33\x44\x55\x66"   # src MAC
            b"\x08\x06"                    # EtherType: ARP
            + b"\x00" * 20
        )
        pkt = parse_packet(arp_frame)
        self.assertIsInstance(pkt.ethernet, EthernetHeader)
        self.assertIsNone(pkt.ip)
        self.assertIsNone(pkt.transport)


class TestParsedPacketTimestamps(unittest.TestCase):
    def test_default_timestamps_are_zero(self):
        pkt = ParsedPacket()
        self.assertEqual(pkt.ts_sec, 0)
        self.assertEqual(pkt.ts_frac, 0)

    def test_parse_packet_leaves_timestamps_zero(self):
        pkt = parse_packet(_tcp())
        self.assertEqual(pkt.ts_sec, 0)
        self.assertEqual(pkt.ts_frac, 0)


class TestParsePcapPacket(unittest.TestCase):
    def _make_pcap(self, packets: list, nanoseconds: bool = False) -> object:
        buf = io.BytesIO()
        write_pcap(packets, file_object=buf, nanoseconds=nanoseconds)
        buf.seek(0)
        return read_pcap(file_object=buf)

    def test_timestamp_propagated(self):
        raw = _tcp()
        pcap = self._make_pcap([(raw, 1234567890, 500_000)])
        pkt = parse_pcap_packet(pcap.packets[0], pcap.header)
        self.assertEqual(pkt.ts_sec, 1234567890)
        self.assertEqual(pkt.ts_frac, 500_000)

    def test_nanosecond_timestamp_propagated(self):
        raw = _tcp()
        pcap = self._make_pcap([(raw, 1000, 999_999_999)], nanoseconds=True)
        pkt = parse_pcap_packet(pcap.packets[0], pcap.header)
        self.assertEqual(pkt.ts_sec, 1000)
        self.assertEqual(pkt.ts_frac, 999_999_999)

    def test_link_type_ethernet_parsed(self):
        raw = _tcp(src_port=1111, dst_port=2222)
        pcap = self._make_pcap([(raw, 0, 0)])
        pkt = parse_pcap_packet(pcap.packets[0], pcap.header)
        self.assertIsInstance(pkt.ethernet, EthernetHeader)
        self.assertIsInstance(pkt.ip, IPHeader)
        self.assertIsInstance(pkt.transport, TCPHeader)
        self.assertEqual(pkt.transport.dst_port, 2222)

    def test_link_type_raw_ip_parsed(self):
        raw_full = _tcp(src_port=3333, dst_port=4444)
        raw_ip = raw_full[14:]  # strip Ethernet header
        pcap = self._make_pcap([(raw_ip, 0, 0)], nanoseconds=False)
        # Patch the header to LINKTYPE_RAW since write_pcap defaults to Ethernet
        from packeteer.pcap import PcapFileHeader
        raw_header = PcapFileHeader(
            link_type=LINKTYPE_RAW,
            version_major=pcap.header.version_major,
            version_minor=pcap.header.version_minor,
            snaplen=pcap.header.snaplen,
            nanoseconds=pcap.header.nanoseconds,
        )
        pkt = parse_pcap_packet(pcap.packets[0], raw_header)
        self.assertIsNone(pkt.ethernet)
        self.assertIsInstance(pkt.ip, IPHeader)
        self.assertIsInstance(pkt.transport, TCPHeader)
        self.assertEqual(pkt.transport.dst_port, 4444)

    def test_multiple_records(self):
        r1 = _tcp(dst_port=80)
        r2 = _udp(dst_port=53)
        pcap = self._make_pcap([(r1, 1000, 0), (r2, 1001, 0)])
        p1 = parse_pcap_packet(pcap.packets[0], pcap.header)
        p2 = parse_pcap_packet(pcap.packets[1], pcap.header)
        self.assertIsInstance(p1.transport, TCPHeader)
        self.assertEqual(p1.transport.dst_port, 80)
        self.assertIsInstance(p2.transport, UDPHeader)
        self.assertEqual(p2.transport.dst_port, 53)
        self.assertEqual(p1.ts_sec, 1000)
        self.assertEqual(p2.ts_sec, 1001)


class TestParsePcapFile(unittest.TestCase):
    def _make_buf(self, packets: list, nanoseconds: bool = False) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap(packets, file_object=buf, nanoseconds=nanoseconds)
        buf.seek(0)
        return buf

    def test_returns_json_string(self):
        buf = self._make_buf([(_tcp(), 0, 0)])
        result = parse_pcap_file(file_object=buf)
        self.assertIsInstance(result, str)

    def test_valid_json(self):
        buf = self._make_buf([(_tcp(), 0, 0)])
        import json
        parsed = json.loads(parse_pcap_file(file_object=buf))
        self.assertIn("packets", parsed)

    def test_packet_count(self):
        import json
        buf = self._make_buf([(_tcp(), 0, 0), (_udp(), 1, 0), (_icmp(), 2, 0)])
        result = json.loads(parse_pcap_file(file_object=buf))
        self.assertEqual(len(result["packets"]), 3)

    def test_network_fields(self):
        import json
        buf = self._make_buf([(_tcp(src_port=1234, dst_port=443), 0, 0)])
        result = json.loads(parse_pcap_file(file_object=buf))
        net = result["packets"][0]["network"]
        self.assertEqual(net["src"], "10.0.0.1")
        self.assertEqual(net["dst"], "10.0.0.2")
        self.assertEqual(net["protocol"], "tcp")

    def test_transport_fields(self):
        import json
        buf = self._make_buf([(_tcp(src_port=1234, dst_port=443), 0, 0)])
        result = json.loads(parse_pcap_file(file_object=buf))
        t = result["packets"][0]["transport"]
        self.assertEqual(t["src_port"], 1234)
        self.assertEqual(t["dst_port"], 443)

    def test_timestamps_in_per_packet_metadata(self):
        import json
        buf = self._make_buf([(_tcp(), 1000, 500_000)])
        result = json.loads(parse_pcap_file(file_object=buf))
        out = result["packets"][0]["packet_metadata"]
        self.assertEqual(out["timestamp_s"], 1000)
        self.assertEqual(out["timestamp_us"], 500_000)

    def test_nanosecond_timestamps_use_ns_key(self):
        import json
        buf = self._make_buf([(_tcp(), 1000, 999_999_999)], nanoseconds=True)
        result = json.loads(parse_pcap_file(file_object=buf))
        out = result["packets"][0]["packet_metadata"]
        self.assertIn("timestamp_ns", out)
        self.assertNotIn("timestamp_us", out)
        self.assertEqual(out["timestamp_ns"], 999_999_999)

    def test_nanoseconds_flag_in_file_metadata(self):
        import json
        buf = self._make_buf([(_tcp(), 0, 0)], nanoseconds=True)
        result = json.loads(parse_pcap_file(file_object=buf))
        self.assertTrue(result["metadata"]["nanoseconds"])

    def test_nanoseconds_false_in_file_metadata_for_usec(self):
        import json
        buf = self._make_buf([(_tcp(), 0, 0)], nanoseconds=False)
        result = json.loads(parse_pcap_file(file_object=buf))
        self.assertFalse(result["metadata"]["nanoseconds"])

    def test_extra_file_metadata_fields_merged(self):
        import json
        buf = self._make_buf([(_tcp(), 0, 0)])
        result = json.loads(parse_pcap_file(file_object=buf, output={"from_file": "capture.pcap"}))
        self.assertEqual(result["metadata"]["from_file"], "capture.pcap")

    def test_nanoseconds_and_extra_file_metadata_merged(self):
        import json
        buf = self._make_buf([(_tcp(), 0, 0)], nanoseconds=True)
        result = json.loads(parse_pcap_file(file_object=buf, output={"from_file": "capture.pcap"}))
        self.assertTrue(result["metadata"]["nanoseconds"])
        self.assertEqual(result["metadata"]["from_file"], "capture.pcap")

    def test_empty_pcap(self):
        import json
        buf = self._make_buf([])
        result = json.loads(parse_pcap_file(file_object=buf))
        self.assertEqual(result["packets"], [])


def _ipv4_with_proto(proto: int) -> bytes:
    """Build an IPv4 packet with an arbitrary protocol number patched in."""
    raw = bytearray(PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build())
    raw[9] = proto   # IPv4 protocol field
    raw[10] = 0      # checksum not recalculated after mutation; parser does not validate it
    raw[11] = 0
    return bytes(raw)


class TestUnsupportedIPProtocol(unittest.TestCase):
    """parse_packet behaviour when the IP protocol number is not recognised."""

    def _build_with_proto(self, proto: int) -> bytes:
        return _ipv4_with_proto(proto)

    def test_warning_category(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning):
            parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)

    def test_warning_protocol_attribute(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)
        self.assertEqual(ctx.warning.protocol, 89)

    def test_warning_message_mentions_payload(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)
        self.assertIn("payload", str(ctx.warning).lower())

    def test_transport_is_none(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning):
            pkt = parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)
        self.assertIsNone(pkt.transport)

    def test_ip_is_parsed(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning):
            pkt = parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)
        assert isinstance(pkt.ip, IPHeader)
        self.assertEqual(pkt.ip.protocol, 89)

    def test_remaining_bytes_in_payload(self) -> None:
        with self.assertWarns(UnsupportedIPProtocolWarning):
            pkt = parse_packet(self._build_with_proto(89), link_type=LINKTYPE_RAW)
        self.assertGreater(len(pkt.payload), 0)

    def test_no_warning_for_known_protocol(self) -> None:
        import warnings
        raw = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build()
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            pkt = parse_packet(raw, link_type=LINKTYPE_RAW)
        self.assertIsNotNone(pkt.transport)


class TestParsePcapFileWarning(unittest.TestCase):
    """parse_pcap_file emits a summary UnsupportedIPProtocolWarning."""

    def _make_buf(
        self,
        packets: list[tuple[bytes, int, int]],
        *,
        link_type: int = LINKTYPE_RAW,
    ) -> io.BytesIO:
        buf = io.BytesIO()
        write_pcap(packets, file_object=buf, link_type=link_type)
        buf.seek(0)
        return buf

    def _ospf(self, ts: int = 0) -> tuple[bytes, int, int]:
        return (_ipv4_with_proto(89), ts, 0)

    def test_single_unsupported_packet_warns(self) -> None:
        buf = self._make_buf([self._ospf()])
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_pcap_file(file_object=buf)
        self.assertEqual(ctx.warning.protocol, 89)

    def test_count_in_message(self) -> None:
        buf = self._make_buf([self._ospf(0), self._ospf(1), self._ospf(2)])
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_pcap_file(file_object=buf)
        self.assertIn("3 packets", str(ctx.warning))

    def test_singular_count_in_message(self) -> None:
        buf = self._make_buf([self._ospf()])
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_pcap_file(file_object=buf)
        self.assertIn("1 packet", str(ctx.warning))
        self.assertNotIn("1 packets", str(ctx.warning))

    def test_file_path_in_message(self) -> None:
        import os
        import tempfile
        raw, ts, frac = self._ospf()
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            write_pcap([(raw, ts, frac)], file_object=f, link_type=LINKTYPE_RAW)
            tmp = f.name
        try:
            with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
                parse_pcap_file(path=tmp)
            self.assertIn(tmp, str(ctx.warning))
        finally:
            os.unlink(tmp)

    def test_no_path_hint_for_file_object(self) -> None:
        buf = self._make_buf([self._ospf()])
        with self.assertWarns(UnsupportedIPProtocolWarning) as ctx:
            parse_pcap_file(file_object=buf)
        self.assertNotIn(" in '", str(ctx.warning))

    def test_one_warning_per_distinct_protocol(self) -> None:
        buf = self._make_buf([self._ospf(), (_ipv4_with_proto(112), 1, 0)])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            parse_pcap_file(file_object=buf)
        unsupported = [w for w in caught if issubclass(w.category, UnsupportedIPProtocolWarning)]
        protos = {w.message.protocol for w in unsupported}
        self.assertEqual(protos, {89, 112})

    def test_no_warning_for_supported_protocols(self) -> None:
        import warnings
        raw = PacketBuilder().ip(src="10.0.0.1", dst="10.0.0.2").tcp().build()
        buf = self._make_buf([(raw, 0, 0)])
        with warnings.catch_warnings():
            warnings.simplefilter("error", UnsupportedIPProtocolWarning)
            parse_pcap_file(file_object=buf)  # must not raise


if __name__ == "__main__":
    unittest.main()
