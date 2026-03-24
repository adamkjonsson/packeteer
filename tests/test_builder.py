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


if __name__ == '__main__':
    unittest.main()
