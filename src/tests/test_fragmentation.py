"""Tests for IP fragmentation — RFC 791 (IPv4) and RFC 8200 §4.5 (IPv6)."""
from __future__ import annotations

import socket
import struct
import unittest

from packeteer.generate import PacketBuilder, fragment_ipv4, fragment_ipv6
from packeteer.generate.ethernet import ETHERTYPE_IPV4, ETHERTYPE_IPV6, EthernetHeader
from packeteer.generate.ip import IPHeader
from packeteer.generate.ipv6 import IPv6Header

# ---------------------------------------------------------------------------
# IPv4 fragmentation
# ---------------------------------------------------------------------------

class TestFragmentIPv4(unittest.TestCase):

    def _make_hdr(self, proto: int = socket.IPPROTO_UDP) -> IPHeader:
        return IPHeader("10.0.0.1", "10.0.0.2", proto, ttl=64)

    # --- fragment count -------------------------------------------------------

    def test_single_fragment_when_data_fits(self):
        data = b"\xab" * 100
        frags = fragment_ipv4(self._make_hdr(), data, mtu=1500)
        self.assertEqual(len(frags), 1)

    def test_two_fragments(self):
        # MTU=576 → max_data=(576-20)&~7 = 556 bytes per fragment
        data = b"\xaa" * 700
        frags = fragment_ipv4(self._make_hdr(), data, mtu=576)
        self.assertEqual(len(frags), 2)

    def test_three_fragments(self):
        # MTU=200 → max_data=(200-20)&~7 = 176 bytes per fragment
        data = b"\xbb" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        self.assertEqual(len(frags), 3)

    # --- payload reassembly ---------------------------------------------------

    def test_payload_reassembles_correctly(self):
        data = bytes(range(256)) * 4  # 1024 bytes
        frags = fragment_ipv4(self._make_hdr(), data, mtu=300)
        reassembled = b"".join(f[20:] for f in frags)  # strip 20-byte IP header each time
        self.assertEqual(reassembled, data)

    # --- IPv4 header fields ---------------------------------------------------

    def test_ip_header_version_and_ihl(self):
        frags = fragment_ipv4(self._make_hdr(), b"\x00" * 200, mtu=100)
        for frag in frags:
            self.assertEqual(frag[0], 0x45)  # version=4, IHL=5

    def test_shared_identification(self):
        frags = fragment_ipv4(self._make_hdr(), b"\x00" * 500, mtu=200)
        ids = [struct.unpack("!H", f[4:6])[0] for f in frags]
        self.assertTrue(
            all(i == ids[0] for i in ids),
            "All fragments must share the same identification",
        )

    def test_mf_flag_set_on_all_but_last(self):
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        for frag in frags[:-1]:
            flags_frag = struct.unpack("!H", frag[6:8])[0]
            mf = (flags_frag >> 13) & 0x1  # bit 2 of 3-bit flags field = MF
            self.assertEqual(mf, 1, "MF must be set on all but the last fragment")

    def test_mf_flag_clear_on_last(self):
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        flags_frag = struct.unpack("!H", frags[-1][6:8])[0]
        mf = (flags_frag >> 13) & 0x1
        self.assertEqual(mf, 0, "MF must be clear on the last fragment")

    def test_df_flag_always_clear(self):
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        for frag in frags:
            flags_frag = struct.unpack("!H", frag[6:8])[0]
            df = (flags_frag >> 14) & 0x1
            self.assertEqual(df, 0, "DF must be clear on all fragments")

    def test_fragment_offsets_are_correct(self):
        # MTU=200 → max_data=176 bytes → offsets 0, 22, 44 (in 8-byte units)
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        expected_offset = 0
        for frag in frags:
            flags_frag = struct.unpack("!H", frag[6:8])[0]
            offset_units = flags_frag & 0x1FFF  # low 13 bits
            self.assertEqual(offset_units, expected_offset // 8)
            # advance by max_data=176
            expected_offset += 176 if frag is not frags[-1] else 0

    def test_ip_checksum_valid_on_each_fragment(self):
        """Re-compute the checksum and verify it equals zero (RFC 1071)."""
        from packeteer.generate.checksum import ones_complement_checksum
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        for frag in frags:
            ip_hdr_bytes = frag[:20]
            # ones_complement_checksum over the header (including embedded checksum) == 0
            self.assertEqual(ones_complement_checksum(ip_hdr_bytes), 0)

    def test_total_length_field(self):
        data = b"\x00" * 500
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        for frag in frags:
            total_length = struct.unpack("!H", frag[2:4])[0]
            self.assertEqual(total_length, len(frag))  # no Ethernet header

    def test_protocol_preserved(self):
        data = b"\x00" * 200
        frags = fragment_ipv4(
            IPHeader("1.2.3.4", "5.6.7.8", socket.IPPROTO_TCP, ttl=128),
            data, mtu=100,
        )
        for frag in frags:
            self.assertEqual(frag[9], socket.IPPROTO_TCP)

    def test_ttl_preserved(self):
        data = b"\x00" * 200
        frags = fragment_ipv4(
            IPHeader("1.2.3.4", "5.6.7.8", socket.IPPROTO_UDP, ttl=128),
            data, mtu=100,
        )
        for frag in frags:
            self.assertEqual(frag[8], 128)

    # --- Ethernet header ------------------------------------------------------

    def test_with_ethernet_header(self):
        eth = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV4)
        data = b"\x00" * 200
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200, eth_header=eth)
        for frag in frags:
            # First 14 bytes are Ethernet, next byte is 0x45 (IPv4 version+IHL)
            self.assertEqual(frag[14], 0x45)

    def test_without_ethernet_header(self):
        data = b"\x00" * 200
        frags = fragment_ipv4(self._make_hdr(), data, mtu=200)
        for frag in frags:
            self.assertEqual(frag[0], 0x45)  # starts directly with IP header

    # --- identification -------------------------------------------------------

    def test_identification_reused_from_header(self):
        hdr = IPHeader("1.1.1.1", "2.2.2.2", socket.IPPROTO_UDP, identification=0xBEEF)
        frags = fragment_ipv4(hdr, b"\x00" * 500, mtu=200)
        for frag in frags:
            ident = struct.unpack("!H", frag[4:6])[0]
            self.assertEqual(ident, 0xBEEF)

    # --- error handling -------------------------------------------------------

    def test_mtu_too_small_raises(self):
        with self.assertRaises(ValueError):
            fragment_ipv4(self._make_hdr(), b"\x00" * 100, mtu=27)  # 27-20=7 < 8


# ---------------------------------------------------------------------------
# IPv6 fragmentation
# ---------------------------------------------------------------------------

_IPV6_HDR_LEN = 40
_IPV6_FRAG_EXT_LEN = 8
_NEXT_HEADER_FRAGMENT = 44


class TestFragmentIPv6(unittest.TestCase):

    def _make_hdr(self, next_header: int = 17) -> IPv6Header:
        return IPv6Header("::1", "::2", next_header=next_header, hop_limit=64)

    # --- fragment count -------------------------------------------------------

    def test_single_fragment_when_data_fits(self):
        data = b"\xcc" * 100
        frags = fragment_ipv6(self._make_hdr(), data, mtu=1500)
        self.assertEqual(len(frags), 1)

    def test_two_fragments(self):
        # MTU=576 → max_data=(576-40-8)&~7 = 528 bytes
        data = b"\xdd" * 700
        frags = fragment_ipv6(self._make_hdr(), data, mtu=576)
        self.assertEqual(len(frags), 2)

    def test_three_fragments(self):
        # MTU=200 → max_data=(200-40-8)&~7 = 152 bytes
        data = b"\xee" * 400
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200)
        self.assertEqual(len(frags), 3)

    # --- payload reassembly ---------------------------------------------------

    def test_payload_reassembles_correctly(self):
        data = bytes(range(256)) * 4  # 1024 bytes
        frags = fragment_ipv6(self._make_hdr(), data, mtu=300)
        # Strip 40-byte IPv6 base header + 8-byte fragment extension header
        reassembled = b"".join(f[_IPV6_HDR_LEN + _IPV6_FRAG_EXT_LEN:] for f in frags)
        self.assertEqual(reassembled, data)

    # --- IPv6 base header fields ----------------------------------------------

    def test_ipv6_version_nibble(self):
        frags = fragment_ipv6(self._make_hdr(), b"\x00" * 200, mtu=100)
        for frag in frags:
            version = frag[0] >> 4
            self.assertEqual(version, 6)

    def test_ipv6_base_next_header_is_44(self):
        """The IPv6 base header's next_header must be 44 (Fragment) on every fragment."""
        frags = fragment_ipv6(self._make_hdr(), b"\x00" * 500, mtu=200)
        for frag in frags:
            self.assertEqual(frag[6], _NEXT_HEADER_FRAGMENT)

    def test_ipv6_payload_length_field(self):
        """payload_length in the IPv6 base header = frag_ext_hdr + chunk."""
        data = b"\x00" * 500
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200)
        for frag in frags:
            payload_length = struct.unpack("!H", frag[4:6])[0]
            # payload_length = everything after the 40-byte base header
            self.assertEqual(payload_length, len(frag) - _IPV6_HDR_LEN)

    # --- Fragment Extension Header fields -------------------------------------

    def test_frag_ext_next_header_carries_transport_proto(self):
        """Extension header's next_header must be the original transport proto."""
        frags = fragment_ipv6(
            IPv6Header("::1", "::2", next_header=6),  # TCP
            b"\x00" * 500, mtu=200,
        )
        for frag in frags:
            ext_next_header = frag[_IPV6_HDR_LEN]
            self.assertEqual(ext_next_header, 6)

    def test_shared_identification(self):
        frags = fragment_ipv6(self._make_hdr(), b"\x00" * 500, mtu=200)
        ids = [struct.unpack("!I", f[_IPV6_HDR_LEN + 4: _IPV6_HDR_LEN + 8])[0] for f in frags]
        self.assertTrue(all(i == ids[0] for i in ids))

    def test_m_flag_set_on_all_but_last(self):
        data = b"\x00" * 500
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200)
        for frag in frags[:-1]:
            offset_m = struct.unpack("!H", frag[_IPV6_HDR_LEN + 2: _IPV6_HDR_LEN + 4])[0]
            m_flag = offset_m & 0x1
            self.assertEqual(m_flag, 1)

    def test_m_flag_clear_on_last(self):
        data = b"\x00" * 500
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200)
        offset_m = struct.unpack("!H", frags[-1][_IPV6_HDR_LEN + 2: _IPV6_HDR_LEN + 4])[0]
        m_flag = offset_m & 0x1
        self.assertEqual(m_flag, 0)

    def test_fragment_offsets_are_correct(self):
        # MTU=200 → max_data=(200-40-8)&~7=152 bytes
        data = b"\x00" * 400
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200)
        expected_byte_offset = 0
        for frag in frags:
            offset_m = struct.unpack("!H", frag[_IPV6_HDR_LEN + 2: _IPV6_HDR_LEN + 4])[0]
            offset_units = offset_m >> 3  # top 13 bits
            self.assertEqual(offset_units, expected_byte_offset // 8)
            expected_byte_offset += 152 if frag is not frags[-1] else 0

    # --- Ethernet header ------------------------------------------------------

    def test_with_ethernet_header(self):
        eth = EthernetHeader("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66", ETHERTYPE_IPV6)
        data = b"\x00" * 200
        frags = fragment_ipv6(self._make_hdr(), data, mtu=200, eth_header=eth)
        for frag in frags:
            # Ethernet type bytes at offset 12-13 must be 0x86DD
            self.assertEqual(struct.unpack("!H", frag[12:14])[0], 0x86DD)
            # IPv6 version starts at offset 14
            self.assertEqual(frag[14] >> 4, 6)

    # --- error handling -------------------------------------------------------

    def test_mtu_too_small_raises(self):
        with self.assertRaises(ValueError):
            fragment_ipv6(self._make_hdr(), b"\x00" * 100, mtu=47)  # 47-40-8=-1 < 8


# ---------------------------------------------------------------------------
# PacketBuilder.fragment() integration
# ---------------------------------------------------------------------------

class TestPacketBuilderFragment(unittest.TestCase):

    def test_ipv4_udp_single_fragment(self):
        frags = (PacketBuilder()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp()
                 .payload(size=100)
                 .fragment(mtu=1500))
        self.assertEqual(len(frags), 1)

    def test_ipv4_udp_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp()
                 .payload(size=2000)
                 .fragment(mtu=576))
        self.assertGreater(len(frags), 1)

    def test_ipv4_tcp_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="192.168.1.1", dst="192.168.1.2")
                 .tcp()
                 .payload(size=3000)
                 .fragment(mtu=1500))
        self.assertGreater(len(frags), 1)

    def test_ipv4_icmp_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="1.2.3.4", dst="5.6.7.8")
                 .icmp()
                 .payload(size=1000)
                 .fragment(mtu=576))
        self.assertGreater(len(frags), 1)

    def test_ipv6_udp_single_fragment(self):
        frags = (PacketBuilder()
                 .ip(src="::1", dst="::2")
                 .udp()
                 .payload(size=100)
                 .fragment(mtu=1500))
        self.assertEqual(len(frags), 1)

    def test_ipv6_udp_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="fe80::1", dst="fe80::2")
                 .udp()
                 .payload(size=2000)
                 .fragment(mtu=1280))
        self.assertGreater(len(frags), 1)

    def test_ipv6_tcp_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="::1", dst="::2")
                 .tcp()
                 .payload(size=3000)
                 .fragment(mtu=1280))
        self.assertGreater(len(frags), 1)

    def test_ipv6_icmpv6_multiple_fragments(self):
        frags = (PacketBuilder()
                 .ip(src="::1", dst="::2")
                 .icmpv6()
                 .payload(size=2000)
                 .fragment(mtu=1280))
        self.assertGreater(len(frags), 1)

    def test_no_ethernet_ipv4(self):
        frags = (PacketBuilder()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp()
                 .payload(size=1000)
                 .fragment(mtu=576))
        for frag in frags:
            self.assertEqual(frag[0], 0x45)  # IP header starts at byte 0

    def test_no_ethernet_ipv6(self):
        frags = (PacketBuilder()
                 .ip(src="::1", dst="::2")
                 .udp()
                 .payload(size=1000)
                 .fragment(mtu=576))
        for frag in frags:
            self.assertEqual(frag[0] >> 4, 6)  # IPv6 version starts at byte 0

    def test_payload_consistency_across_calls(self):
        """fragment() must use the same cached payload bytes on repeated calls."""
        builder = (PacketBuilder()
                   .ip(src="10.0.0.1", dst="10.0.0.2", identification=1234)
                   .udp()
                   .payload(size=100))
        frags1 = builder.fragment(mtu=1500)
        frags2 = builder.fragment(mtu=1500)
        self.assertEqual(frags1, frags2)

    def test_ipv4_fragments_contain_ethernet_ethertype(self):
        frags = (PacketBuilder()
                 .ethernet()
                 .ip(src="10.0.0.1", dst="10.0.0.2")
                 .udp()
                 .payload(size=500)
                 .fragment(mtu=200))
        for frag in frags:
            ethertype = struct.unpack("!H", frag[12:14])[0]
            self.assertEqual(ethertype, 0x0800)

    def test_ipv6_fragments_contain_ethernet_ethertype(self):
        frags = (PacketBuilder()
                 .ethernet()
                 .ip(src="::1", dst="::2")
                 .udp()
                 .payload(size=500)
                 .fragment(mtu=200))
        for frag in frags:
            ethertype = struct.unpack("!H", frag[12:14])[0]
            self.assertEqual(ethertype, 0x86DD)


if __name__ == "__main__":
    unittest.main()
