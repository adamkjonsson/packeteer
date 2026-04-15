import json
import unittest

from packeteer.generate.ethernet import EthernetHeader, VLANTag, ETHERTYPE_IPV4, ETHERTYPE_IPV6
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header
from packeteer.generate.tcp import TCPHeader, TCPOptions, TCP_SYN, TCP_ACK, TCP_PSH
from packeteer.generate.udp import UDPHeader
from packeteer.generate.icmp import ICMPHeader
from packeteer.generate.icmpv6 import ICMPv6Header
from packeteer.generate import PacketBuilder

from packeteer.parse.to_config import update_config, to_packet_spec, to_json_string
from packeteer.parse import (
    ethernet_packet_parser,
    ip_packet_parser,
    tcp_packet_parser,
    udp_packet_parser,
    icmp_packet_parser,
    icmpv6_packet_parser,
)


class TestUpdateConfigEthernet(unittest.TestCase):
    def test_basic_fields(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        cfg = update_config({}, hdr)
        eth = cfg["ethernet"]
        self.assertEqual(eth["src_mac"], "11:22:33:44:55:66")
        self.assertEqual(eth["dst_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(eth["enabled"])

    def test_no_vlan_tag(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        cfg = update_config({}, hdr)
        self.assertNotIn("vlan", cfg["ethernet"])

    def test_vlan_tag(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4,
                             vlan_tag=VLANTag(vid=100, pcp=3, dei=1))
        cfg = update_config({}, hdr)
        vlan = cfg["ethernet"]["vlan"]
        self.assertEqual(vlan["id"], 100)
        self.assertEqual(vlan["pcp"], 3)
        self.assertEqual(vlan["dei"], 1)

    def test_returns_same_dict(self):
        hdr = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        cfg = {}
        result = update_config(cfg, hdr)
        self.assertIs(result, cfg)


class TestUpdateConfigIPv4(unittest.TestCase):
    def test_basic_fields(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, ttl=128)
        cfg = update_config({}, hdr)
        net = cfg["network"]
        self.assertEqual(net["src"], "10.0.0.1")
        self.assertEqual(net["dst"], "10.0.0.2")
        self.assertEqual(net["ttl"], 128)
        self.assertEqual(net["protocol"], "tcp")

    def test_protocol_udp(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 17)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["protocol"], "udp")

    def test_protocol_icmp(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 1)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["protocol"], "icmp")

    def test_default_flags_omitted(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, flags=0b010)
        cfg = update_config({}, hdr)
        self.assertNotIn("flags", cfg["network"])

    def test_non_default_flags_included(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, flags=0)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["flags"], 0)

    def test_default_tos_omitted(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, tos=0)
        cfg = update_config({}, hdr)
        self.assertNotIn("tos", cfg["network"])

    def test_non_default_tos_included(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, tos=16)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["tos"], 16)

    def test_identification_included_when_nonzero(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, identification=1234)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["identification"], 1234)

    def test_fragment_offset_included_when_nonzero(self):
        hdr = IPHeader("10.0.0.1", "10.0.0.2", 6, fragment_offset=8)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["fragment_offset"], 8)


class TestUpdateConfigIPv6(unittest.TestCase):
    def test_basic_fields(self):
        hdr = IPv6Header("::1", "::2", next_header=6, hop_limit=64)
        cfg = update_config({}, hdr)
        net = cfg["network"]
        self.assertEqual(net["src"], "::1")
        self.assertEqual(net["dst"], "::2")
        self.assertEqual(net["ttl"], 64)
        self.assertEqual(net["protocol"], "tcp")

    def test_protocol_icmpv6(self):
        hdr = IPv6Header("::1", "::2", next_header=58)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["protocol"], "icmpv6")

    def test_default_traffic_class_omitted(self):
        hdr = IPv6Header("::1", "::2", next_header=6, traffic_class=0)
        cfg = update_config({}, hdr)
        self.assertNotIn("traffic_class", cfg["network"])

    def test_non_default_traffic_class_included(self):
        hdr = IPv6Header("::1", "::2", next_header=6, traffic_class=8)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["traffic_class"], 8)

    def test_flow_label_included_when_nonzero(self):
        hdr = IPv6Header("::1", "::2", next_header=6, flow_label=12345)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["network"]["flow_label"], 12345)


class TestUpdateConfigTCP(unittest.TestCase):
    def test_basic_fields(self):
        hdr = TCPHeader(src_port=12345, dst_port=80, seq=100, ack=200,
                        flags=TCP_PSH | TCP_ACK, window=8192)
        cfg = update_config({}, hdr)
        t = cfg["transport"]
        self.assertEqual(t["src_port"], 12345)
        self.assertEqual(t["dst_port"], 80)
        self.assertEqual(t["seq"], 100)
        self.assertEqual(t["ack"], 200)
        self.assertEqual(t["flags"], TCP_PSH | TCP_ACK)
        self.assertEqual(t["window"], 8192)

    def test_reserved_omitted_when_zero(self):
        hdr = TCPHeader(src_port=1, dst_port=2)
        cfg = update_config({}, hdr)
        self.assertNotIn("reserved", cfg["transport"])

    def test_urgent_ptr_omitted_when_zero(self):
        hdr = TCPHeader(src_port=1, dst_port=2)
        cfg = update_config({}, hdr)
        self.assertNotIn("urgent_ptr", cfg["transport"])

    def test_urgent_ptr_included_when_set(self):
        hdr = TCPHeader(src_port=1, dst_port=2, urgent_ptr=100)
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["transport"]["urgent_ptr"], 100)

    def test_options_mss(self):
        hdr = TCPHeader(src_port=1, dst_port=2,
                        options=TCPOptions(mss=1460))
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["transport"]["options"]["mss"], 1460)

    def test_options_timestamps(self):
        hdr = TCPHeader(src_port=1, dst_port=2,
                        options=TCPOptions(timestamps=(1000, 2000)))
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["transport"]["options"]["timestamps"], [1000, 2000])

    def test_options_sack_permitted(self):
        hdr = TCPHeader(src_port=1, dst_port=2,
                        options=TCPOptions(sack_permitted=True))
        cfg = update_config({}, hdr)
        self.assertTrue(cfg["transport"]["options"]["sack_permitted"])

    def test_options_sack_blocks(self):
        hdr = TCPHeader(src_port=1, dst_port=2,
                        options=TCPOptions(sack_blocks=[(100, 200), (300, 400)]))
        cfg = update_config({}, hdr)
        self.assertEqual(cfg["transport"]["options"]["sack"], [[100, 200], [300, 400]])

    def test_no_options_section_when_none(self):
        hdr = TCPHeader(src_port=1, dst_port=2, options=None)
        cfg = update_config({}, hdr)
        self.assertNotIn("options", cfg["transport"])


class TestUpdateConfigUDP(unittest.TestCase):
    def test_fields(self):
        hdr = UDPHeader(src_port=5000, dst_port=53)
        cfg = update_config({}, hdr)
        t = cfg["transport"]
        self.assertEqual(t["src_port"], 5000)
        self.assertEqual(t["dst_port"], 53)
        self.assertNotIn("seq", t)

    def test_only_port_fields(self):
        hdr = UDPHeader(src_port=5000, dst_port=53)
        cfg = update_config({}, hdr)
        self.assertEqual(set(cfg["transport"].keys()), {"src_port", "dst_port"})


class TestUpdateConfigICMP(unittest.TestCase):
    def test_icmpv4_fields(self):
        hdr = ICMPHeader(type=8, code=0, identifier=42, sequence=7)
        cfg = update_config({}, hdr)
        t = cfg["transport"]
        self.assertEqual(t["type"], 8)
        self.assertEqual(t["code"], 0)
        self.assertEqual(t["identifier"], 42)
        self.assertEqual(t["sequence"], 7)

    def test_icmpv6_fields(self):
        hdr = ICMPv6Header(type=128, code=0, identifier=5, sequence=3)
        cfg = update_config({}, hdr)
        t = cfg["transport"]
        self.assertEqual(t["type"], 128)
        self.assertEqual(t["identifier"], 5)
        self.assertEqual(t["sequence"], 3)


class TestUpdateConfigPayload(unittest.TestCase):
    def test_payload_hex_encoded(self):
        cfg = update_config({}, b"\xde\xad\xbe\xef")
        self.assertEqual(cfg["payload"]["data"], "deadbeef")

    def test_empty_payload(self):
        cfg = update_config({}, b"")
        self.assertEqual(cfg["payload"]["data"], "")

    def test_ascii_payload(self):
        cfg = update_config({}, b"Hello")
        self.assertEqual(cfg["payload"]["data"], "48656c6c6f")


class TestUpdateConfigTypeError(unittest.TestCase):
    def test_unknown_type_raises(self):
        with self.assertRaises(TypeError):
            update_config({}, 42)

    def test_none_raises(self):
        with self.assertRaises(TypeError):
            update_config({}, None)


class TestUpdateConfigChaining(unittest.TestCase):
    def test_chained_calls_build_full_config(self):
        eth = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        ip  = IPHeader("10.0.0.1", "10.0.0.2", 6)
        tcp = TCPHeader(src_port=1234, dst_port=80, flags=TCP_SYN)
        cfg = update_config(update_config(update_config({}, eth), ip), tcp)
        self.assertIn("ethernet", cfg)
        self.assertIn("network", cfg)
        self.assertIn("transport", cfg)

    def test_later_layer_overwrites_earlier(self):
        tcp1 = TCPHeader(src_port=1, dst_port=80)
        tcp2 = TCPHeader(src_port=2, dst_port=443)
        cfg = {}
        update_config(cfg, tcp1)
        update_config(cfg, tcp2)
        self.assertEqual(cfg["transport"]["src_port"], 2)


class TestToJsonConfig(unittest.TestCase):
    def test_packets_key(self):
        p1 = {"network": {"src": "1.2.3.4", "dst": "5.6.7.8", "protocol": "udp"}}
        result = to_packet_spec([p1])
        self.assertEqual(result["packets"], [p1])

    def test_file_metadata_block_included(self):
        result = to_packet_spec([], metadata={"from_file": "capture.pcap", "type": "pcap"})
        self.assertEqual(result["metadata"]["from_file"], "capture.pcap")
        self.assertEqual(result["metadata"]["type"], "pcap")
        self.assertFalse(result["metadata"]["nanoseconds"])  # defaulted

    def test_metadata_always_present_with_nanoseconds(self):
        result = to_packet_spec([])
        self.assertIn("metadata", result)
        self.assertFalse(result["metadata"]["nanoseconds"])

    def test_multiple_packets(self):
        pkts = [{}, {}, {}]
        result = to_packet_spec(pkts)
        self.assertEqual(len(result["packets"]), 3)


class TestToJsonString(unittest.TestCase):
    def test_valid_json(self):
        cfg = to_packet_spec([{"network": {"src": "1.2.3.4", "dst": "5.6.7.8",
                                           "protocol": "tcp", "ttl": 64}}])
        s = to_json_string(cfg)
        parsed = json.loads(s)
        self.assertEqual(parsed["packets"][0]["network"]["src"], "1.2.3.4")

    def test_indentation(self):
        cfg = {"packets": []}
        s2 = to_json_string(cfg, indent=2)
        s4 = to_json_string(cfg, indent=4)
        self.assertIn("  ", s2)
        self.assertIn("    ", s4)


class TestRoundtrip(unittest.TestCase):
    """Parse a packet built by packet_generator and verify the config fields."""

    def _build_and_parse_tcp(self, src_port=12345, dst_port=80, flags=TCP_ACK):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp(src_port=src_port, dst_port=dst_port, flags=flags)
               .build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size, _, ip_hdr = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        tcp_size, _, tcp_hdr = tcp_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, tcp_hdr)
        return cfg

    def test_tcp_addresses(self):
        cfg = self._build_and_parse_tcp()
        self.assertEqual(cfg["network"]["src"], "10.0.0.1")
        self.assertEqual(cfg["network"]["dst"], "10.0.0.2")

    def test_tcp_protocol_string(self):
        cfg = self._build_and_parse_tcp()
        self.assertEqual(cfg["network"]["protocol"], "tcp")

    def test_tcp_ports(self):
        cfg = self._build_and_parse_tcp(src_port=54321, dst_port=443)
        self.assertEqual(cfg["transport"]["src_port"], 54321)
        self.assertEqual(cfg["transport"]["dst_port"], 443)

    def test_tcp_flags(self):
        cfg = self._build_and_parse_tcp(flags=TCP_SYN)
        self.assertEqual(cfg["transport"]["flags"], TCP_SYN)

    def test_udp_roundtrip(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp(src_port=5000, dst_port=53).build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size, _, ip_hdr = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        _, _, udp_hdr = udp_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, udp_hdr)
        self.assertEqual(cfg["network"]["protocol"], "udp")
        self.assertEqual(cfg["transport"]["src_port"], 5000)
        self.assertEqual(cfg["transport"]["dst_port"], 53)

    def test_icmp_roundtrip(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .icmp(identifier=7, sequence=3).build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size, _, ip_hdr = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        _, _, icmp_hdr = icmp_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, icmp_hdr)
        self.assertEqual(cfg["network"]["protocol"], "icmp")
        self.assertEqual(cfg["transport"]["identifier"], 7)
        self.assertEqual(cfg["transport"]["sequence"], 3)

    def test_icmpv6_roundtrip(self):
        raw = (PacketBuilder().ethernet()
               .ip(src="::1", dst="::2")
               .icmpv6(identifier=4, sequence=9).build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size, _, ip_hdr = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        _, _, icmpv6_hdr = icmpv6_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, icmpv6_hdr)
        self.assertEqual(cfg["network"]["protocol"], "icmpv6")
        self.assertEqual(cfg["transport"]["identifier"], 4)
        self.assertEqual(cfg["transport"]["sequence"], 9)

    def test_vlan_roundtrip(self):
        raw = (PacketBuilder().ethernet().vlan(vid=42, pcp=5)
               .ip(src="10.0.0.1", dst="10.0.0.2").udp().build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        self.assertEqual(cfg["ethernet"]["vlan"]["id"], 42)
        self.assertEqual(cfg["ethernet"]["vlan"]["pcp"], 5)

    def test_payload_roundtrip(self):
        payload = b"\xca\xfe\xba\xbe" * 5  # 20 bytes
        raw = (PacketBuilder().ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .udp().payload(data=payload).build())
        cfg = {}
        eth_size, _, eth_hdr = ethernet_packet_parser(raw)
        update_config(cfg, eth_hdr)
        ip_size, _, ip_hdr = ip_packet_parser(raw[eth_size:])
        update_config(cfg, ip_hdr)
        udp_size, _, udp_hdr = udp_packet_parser(raw[eth_size + ip_size:])
        update_config(cfg, udp_hdr)
        raw_payload = raw[eth_size + ip_size + udp_size:]
        update_config(cfg, raw_payload)
        self.assertEqual(cfg["payload"]["data"], payload.hex())

    def test_to_json_string_is_parseable(self):
        cfg = self._build_and_parse_tcp(src_port=1234, dst_port=80)
        full = to_packet_spec([cfg], metadata={"from_file": "capture.pcap", "type": "pcap"})
        parsed = json.loads(to_json_string(full))
        self.assertEqual(parsed["metadata"]["from_file"], "capture.pcap")
        self.assertEqual(parsed["packets"][0]["transport"]["dst_port"], 80)


if __name__ == "__main__":
    unittest.main()
