import unittest
from packet_generator import PacketBuilder, Protocol


class TestPacketBuilderSizes(unittest.TestCase):
    def test_tcp_ipv4_with_ethernet(self):
        pkt = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.TCP, payload_size=10).build()
        self.assertEqual(len(pkt), 14 + 20 + 20 + 10)

    def test_udp_ipv4_with_ethernet(self):
        # 14+20+8 = 42 bytes — padded to 60 by default
        pkt = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.UDP, payload_size=0).build()
        self.assertEqual(len(pkt), 60)

    def test_icmp_ipv4_with_ethernet(self):
        # 14+20+8+4 = 46 bytes — padded to 60 by default
        pkt = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.ICMP, payload_size=4).build()
        self.assertEqual(len(pkt), 60)

    def test_tcp_ipv6_with_ethernet(self):
        pkt = PacketBuilder("::1", "::2", Protocol.TCP, payload_size=10).build()
        self.assertEqual(len(pkt), 14 + 40 + 20 + 10)

    def test_udp_ipv6_with_ethernet(self):
        pkt = PacketBuilder("::1", "::2", Protocol.UDP, payload_size=5).build()
        self.assertEqual(len(pkt), 14 + 40 + 8 + 5)

    def test_icmpv6_with_ethernet(self):
        pkt = PacketBuilder("::1", "::2", Protocol.ICMPv6, payload_size=0).build()
        self.assertEqual(len(pkt), 14 + 40 + 8 + 0)

    def test_no_ethernet(self):
        pkt = PacketBuilder(
            "1.2.3.4", "5.6.7.8", Protocol.TCP, payload_size=0,
            include_ethernet=False,
        ).build()
        self.assertEqual(len(pkt), 20 + 20 + 0)

    def test_no_ethernet_ipv6(self):
        pkt = PacketBuilder(
            "::1", "::2", Protocol.UDP, payload_size=8,
            include_ethernet=False,
        ).build()
        self.assertEqual(len(pkt), 40 + 8 + 8)


class TestPacketBuilderPayload(unittest.TestCase):
    def test_explicit_payload_used(self):
        explicit = b'\xde\xad\xbe\xef'
        builder = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.UDP, payload=explicit)
        pkt = builder.build()
        self.assertEqual(builder.payload, explicit)
        # payload sits at bytes 42–45 (14 eth + 20 ip + 8 udp); remainder is padding
        self.assertIn(explicit, pkt)

    def test_payload_property_stable(self):
        builder = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.TCP, payload_size=8)
        self.assertEqual(builder.payload, builder.payload)

    def test_payload_size_zero(self):
        builder = PacketBuilder("1.2.3.4", "5.6.7.8", Protocol.ICMP, payload_size=0)
        self.assertEqual(builder.payload, b'')


class TestPacketBuilderValidation(unittest.TestCase):
    def test_invalid_ipv4_raises(self):
        with self.assertRaises(OSError):
            PacketBuilder("999.0.0.1", "1.2.3.4", Protocol.TCP).build()

    def test_invalid_ipv6_raises(self):
        with self.assertRaises(OSError):
            PacketBuilder("::xyz", "::2", Protocol.TCP).build()


if __name__ == '__main__':
    unittest.main()
