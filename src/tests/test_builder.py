import struct
import unittest
from packet_generator import PacketBuilder


class TestPacketBuilderSizes(unittest.TestCase):
    def test_tcp_ipv4_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="1.2.3.4", dst="5.6.7.8").tcp().payload(size=10).build()
        self.assertEqual(len(pkt), 14 + 20 + 20 + 10)

    def test_udp_ipv4_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        self.assertEqual(len(pkt), 14 + 20 + 8)

    def test_icmp_ipv4_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="1.2.3.4", dst="5.6.7.8").icmp().payload(size=4).build()
        self.assertEqual(len(pkt), 14 + 20 + 8 + 4)

    def test_tcp_ipv6_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="::1", dst="::2").tcp().payload(size=10).build()
        self.assertEqual(len(pkt), 14 + 40 + 20 + 10)

    def test_udp_ipv6_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="::1", dst="::2").udp().payload(size=5).build()
        self.assertEqual(len(pkt), 14 + 40 + 8 + 5)

    def test_icmpv6_with_ethernet(self):
        pkt = PacketBuilder().ethernet().ip(src="::1", dst="::2").icmpv6().build()
        self.assertEqual(len(pkt), 14 + 40 + 8)

    def test_no_ethernet(self):
        pkt = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").tcp().build()
        self.assertEqual(len(pkt), 20 + 20)

    def test_no_ethernet_ipv6(self):
        pkt = PacketBuilder().ip(src="::1", dst="::2").udp().payload(size=8).build()
        self.assertEqual(len(pkt), 40 + 8 + 8)

    def test_ethernet_padding(self):
        pkt = PacketBuilder().ethernet(pad=True).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        self.assertEqual(len(pkt), 60)


class TestPacketBuilderPayload(unittest.TestCase):
    def test_explicit_payload_used(self):
        explicit = b'\xde\xad\xbe\xef'
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="1.2.3.4", dst="5.6.7.8")
               .udp()
               .payload(data=explicit)
               .build())
        self.assertIn(explicit, pkt)

    def test_payload_bytes_stable(self):
        builder = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").tcp().payload(size=8)
        pkt1 = builder.build()
        pkt2 = builder.build()
        self.assertEqual(pkt1, pkt2)

    def test_payload_size_zero(self):
        pkt = PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").icmp().build()
        self.assertEqual(len(pkt), 20 + 8)


class TestPacketBuilderValidation(unittest.TestCase):
    def test_invalid_ipv4_raises(self):
        with self.assertRaises(OSError):
            PacketBuilder().ip(src="999.0.0.1", dst="1.2.3.4")

    def test_invalid_ipv6_raises(self):
        with self.assertRaises(OSError):
            PacketBuilder().ip(src="::xyz", dst="::2")

    def test_no_ip_raises(self):
        with self.assertRaises(ValueError):
            PacketBuilder().tcp().build()

    def test_no_transport_raises(self):
        with self.assertRaises(ValueError):
            PacketBuilder().ip(src="1.2.3.4", dst="5.6.7.8").build()


class TestPacketBuilderVLAN(unittest.TestCase):
    """Single VLAN tag (802.1Q) and QinQ (double-tag) behaviour."""

    def test_single_vlan_size(self):
        # Eth(14) + VLAN(4) + IPv4(20) + UDP(8) = 46
        pkt = PacketBuilder().ethernet().vlan(vid=100).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        self.assertEqual(len(pkt), 14 + 4 + 20 + 8)

    def test_single_vlan_outer_ethertype_is_8021q(self):
        pkt = PacketBuilder().ethernet().vlan(vid=100).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        outer_ethertype, = struct.unpack("!H", pkt[12:14])
        self.assertEqual(outer_ethertype, 0x8100)

    def test_single_vlan_inner_ethertype_is_ipv4(self):
        pkt = PacketBuilder().ethernet().vlan(vid=100).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        inner_ethertype, = struct.unpack("!H", pkt[16:18])
        self.assertEqual(inner_ethertype, 0x0800)

    def test_single_vlan_inner_ethertype_is_ipv6(self):
        pkt = PacketBuilder().ethernet().vlan(vid=100).ip(src="::1", dst="::2").udp().build()
        inner_ethertype, = struct.unpack("!H", pkt[16:18])
        self.assertEqual(inner_ethertype, 0x86DD)

    def test_single_vlan_tci_fields(self):
        pkt = PacketBuilder().ethernet().vlan(vid=300, pcp=5, dei=1).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        tci, = struct.unpack("!H", pkt[14:16])
        self.assertEqual(tci >> 13, 5)        # pcp
        self.assertEqual((tci >> 12) & 1, 1)  # dei
        self.assertEqual(tci & 0x0FFF, 300)   # vid

    def test_qinq_size(self):
        # Eth(14) + VLAN(4) + VLAN(4) + IPv4(20) + UDP(8) = 50
        pkt = PacketBuilder().ethernet().vlan(vid=100).vlan(vid=200).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        self.assertEqual(len(pkt), 14 + 4 + 4 + 20 + 8)

    def test_qinq_ethertypes(self):
        # pkt[12:14] = Eth ethertype (0x8100)
        # pkt[14:16] = outer TCI
        # pkt[16:18] = outer VLAN ethertype (0x8100)
        # pkt[18:20] = inner TCI
        # pkt[20:22] = inner VLAN ethertype (0x0800)
        pkt = PacketBuilder().ethernet().vlan(vid=100).vlan(vid=200).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        eth_etype,  = struct.unpack("!H", pkt[12:14])
        mid_etype,  = struct.unpack("!H", pkt[16:18])
        inner_etype,= struct.unpack("!H", pkt[20:22])
        self.assertEqual(eth_etype,   0x8100)
        self.assertEqual(mid_etype,   0x8100)
        self.assertEqual(inner_etype, 0x0800)

    def test_qinq_vlan_ids(self):
        pkt = PacketBuilder().ethernet().vlan(vid=100).vlan(vid=200).ip(src="1.2.3.4", dst="5.6.7.8").udp().build()
        outer_tci, = struct.unpack("!H", pkt[14:16])
        inner_tci, = struct.unpack("!H", pkt[18:20])
        self.assertEqual(outer_tci & 0x0FFF, 100)
        self.assertEqual(inner_tci & 0x0FFF, 200)


class TestPacketBuilderIPinIP(unittest.TestCase):
    """IP-in-IP and IPv6-in-IPv4 tunnel packet construction."""

    def test_ipv4_in_ipv4_size(self):
        # Eth(14) + outer IPv4(20) + inner IPv4(20) + TCP(20) = 74
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="203.0.113.1", dst="203.0.113.2")
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp()
               .build())
        self.assertEqual(len(pkt), 14 + 20 + 20 + 20)

    def test_ipv4_in_ipv4_outer_proto_is_ipip(self):
        # Outer IP protocol field (byte 9 of IPv4 header) should be 4 (IPIP)
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="203.0.113.1", dst="203.0.113.2")
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp()
               .build())
        self.assertEqual(pkt[14 + 9], 4)

    def test_ipv4_in_ipv4_inner_proto_is_tcp(self):
        # Inner IP protocol field should be 6 (TCP)
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="203.0.113.1", dst="203.0.113.2")
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp()
               .build())
        self.assertEqual(pkt[14 + 20 + 9], 6)

    def test_ipv6_in_ipv4_outer_proto_is_41(self):
        # Outer IPv4 protocol should be 41 (IPv6-in-IPv4, RFC 4213)
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="203.0.113.1", dst="203.0.113.2")
               .ip(src="::1", dst="::2")
               .udp()
               .build())
        self.assertEqual(pkt[14 + 9], 41)

    def test_tcp_checksum_uses_inner_ip(self):
        # In an IP-in-IP stack, TCP checksum must be computed over the inner
        # IP addresses.  Build the same transport with and without the outer IP
        # and verify the TCP header bytes are identical.
        inner_only = (PacketBuilder()
                      .ip(src="10.0.0.1", dst="10.0.0.2")
                      .tcp(src_port=1234, dst_port=80)
                      .build())
        tunneled = (PacketBuilder()
                    .ip(src="203.0.113.1", dst="203.0.113.2")
                    .ip(src="10.0.0.1", dst="10.0.0.2")
                    .tcp(src_port=1234, dst_port=80)
                    .build())
        # TCP header: starts at byte 20 in inner_only, byte 40 in tunneled
        self.assertEqual(inner_only[20:40], tunneled[40:60])


if __name__ == '__main__':
    unittest.main()
