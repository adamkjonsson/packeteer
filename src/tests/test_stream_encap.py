"""Tests for packet_generator.stream_encap — encapsulation helpers."""
from __future__ import annotations

import struct
import unittest

from packeteer.generator.stream_encap import (
    VLANEncap, QinQEncap, MPLSEncap, PPPoEEncap,
    GREEncap, EtherIPEncap, IPIPEncap,
    _as_list, _apply_encap, _encap_ip_start, _fix_encap_prefix,
)
from packeteer.generator.builder import PacketBuilder
from packeteer.generator.tcp_stream import generate_tcp_stream
from packeteer.generator.udp_stream import generate_udp_stream
from packeteer.generator.sctp_stream import generate_sctp_stream


# ── _as_list ──────────────────────────────────────────────────────────────────

class TestAsList(unittest.TestCase):

    def test_none_returns_empty(self):
        self.assertEqual(_as_list(None), [])

    def test_single_encap_wrapped_in_list(self):
        v = VLANEncap(vid=10)
        result = _as_list(v)
        self.assertEqual(result, [v])

    def test_list_returned_as_is(self):
        layers = [VLANEncap(vid=10), MPLSEncap(labels=[100])]
        self.assertIs(_as_list(layers), layers)

    def test_empty_list_returned_as_is(self):
        self.assertEqual(_as_list([]), [])


# ── _encap_ip_start ───────────────────────────────────────────────────────────

class TestEncapIpStart(unittest.TestCase):

    def test_no_encap_with_ethernet(self):
        self.assertEqual(_encap_ip_start(None, True), 14)

    def test_no_encap_no_ethernet(self):
        self.assertEqual(_encap_ip_start(None, False), 0)

    def test_vlan_with_ethernet(self):
        # 14 (eth) + 4 (vlan tag)
        self.assertEqual(_encap_ip_start(VLANEncap(vid=100), True), 18)

    def test_vlan_no_ethernet(self):
        self.assertEqual(_encap_ip_start(VLANEncap(vid=100), False), 4)

    def test_qinq_with_ethernet(self):
        # 14 + 8
        self.assertEqual(_encap_ip_start(QinQEncap(outer_vid=100, inner_vid=200), True), 22)

    def test_mpls_single_label(self):
        # 14 + 4
        self.assertEqual(_encap_ip_start(MPLSEncap(labels=[100]), True), 18)

    def test_mpls_two_labels(self):
        # 14 + 8
        self.assertEqual(_encap_ip_start(MPLSEncap(labels=[100, 200]), True), 22)

    def test_mpls_three_labels(self):
        # 14 + 12
        self.assertEqual(_encap_ip_start(MPLSEncap(labels=[100, 200, 300]), True), 26)

    def test_pppoe_with_ethernet(self):
        # 14 + 8 (PPPoE header 6 + PPP field 2)
        self.assertEqual(_encap_ip_start(PPPoEEncap(session_id=1), True), 22)

    def test_gre_tunnel_stops_at_ethernet(self):
        # Tunnel: outer IP is at standard ethernet offset
        self.assertEqual(_encap_ip_start(GREEncap("1.2.3.4", "5.6.7.8"), True), 14)

    def test_etherip_tunnel_stops_at_ethernet(self):
        self.assertEqual(_encap_ip_start(EtherIPEncap("1.2.3.4", "5.6.7.8"), True), 14)

    def test_ipip_tunnel_stops_at_ethernet(self):
        self.assertEqual(_encap_ip_start(IPIPEncap("1.2.3.4", "5.6.7.8"), True), 14)

    def test_vlan_then_gre_stops_after_vlan(self):
        # 14 (eth) + 4 (vlan) = 18; GRE stops accumulation
        layers = [VLANEncap(vid=100), GREEncap("1.2.3.4", "5.6.7.8")]
        self.assertEqual(_encap_ip_start(layers, True), 18)

    def test_mpls_then_ipip(self):
        # 14 + 4 * 2 = 22
        layers = [MPLSEncap(labels=[100, 200]), IPIPEncap("1.2.3.4", "5.6.7.8")]
        self.assertEqual(_encap_ip_start(layers, True), 22)

    def test_qinq_then_gre(self):
        # 14 + 8 = 22
        layers = [QinQEncap(outer_vid=100, inner_vid=200), GREEncap("1.2.3.4", "5.6.7.8")]
        self.assertEqual(_encap_ip_start(layers, True), 22)

    def test_mpls_empty_labels(self):
        self.assertEqual(_encap_ip_start(MPLSEncap(labels=[]), True), 14)


# ── _fix_encap_prefix ─────────────────────────────────────────────────────────

class TestFixEncapPrefix(unittest.TestCase):

    def test_no_pppoe_returns_prefix_unchanged(self):
        prefix = b'\x00' * 18  # eth + vlan
        result = _fix_encap_prefix(prefix, VLANEncap(vid=100), ip_frag_len=200)
        self.assertIs(result, prefix)

    def test_none_encap_returns_prefix_unchanged(self):
        prefix = b'\x00' * 14
        result = _fix_encap_prefix(prefix, None, ip_frag_len=100)
        self.assertIs(result, prefix)

    def test_pppoe_updates_length_field(self):
        # Build a real PPPoE prefix
        pkt = (PacketBuilder()
               .ethernet()
               .pppoe(session_id=0x1234)
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .tcp(dst_port=80)
               .build())
        ip_start = _encap_ip_start(PPPoEEncap(session_id=0x1234), True)
        prefix = pkt[:ip_start]

        ip_frag_len = 60
        fixed = _fix_encap_prefix(prefix, PPPoEEncap(session_id=0x1234), ip_frag_len)

        # PPPoE payload length at offset 14+4 = 18 (bytes 4-5 of PPPoE header)
        pppoe_start = len(prefix) - 8
        actual_len = struct.unpack_from("!H", fixed, pppoe_start + 4)[0]
        self.assertEqual(actual_len, 2 + ip_frag_len)

    def test_pppoe_length_not_corrupted_for_different_frag_sizes(self):
        prefix = b'\x00' * 22  # eth(14) + pppoe(8)
        for frag_len in (20, 100, 500, 1480):
            fixed = _fix_encap_prefix(prefix, PPPoEEncap(session_id=1), frag_len)
            pppoe_start = len(prefix) - 8
            actual = struct.unpack_from("!H", fixed, pppoe_start + 4)[0]
            self.assertEqual(actual, 2 + frag_len)

    def test_list_with_pppoe_updates(self):
        prefix = b'\x00' * 26  # eth(14) + vlan(4) + pppoe(8)
        layers = [VLANEncap(vid=10), PPPoEEncap(session_id=1)]
        frag_len = 80
        fixed = _fix_encap_prefix(prefix, layers, frag_len)
        pppoe_start = len(prefix) - 8
        actual = struct.unpack_from("!H", fixed, pppoe_start + 4)[0]
        self.assertEqual(actual, 2 + frag_len)


# ── _apply_encap — packet structure ──────────────────────────────────────────

def _build_with_encap(encap, src_ip="10.0.0.1", dst_ip="10.0.0.2") -> bytes:
    b = PacketBuilder().ethernet(src_mac="00:00:00:00:00:01",
                                  dst_mac="00:00:00:00:00:02")
    b = _apply_encap(b, encap, src_mac="00:00:00:00:00:01",
                     dst_mac="00:00:00:00:00:02")
    return b.ip(src=src_ip, dst=dst_ip).tcp(dst_port=80).build()


class TestApplyEncap(unittest.TestCase):

    def test_none_produces_standard_eth_ip_tcp(self):
        pkt = _build_with_encap(None)
        # Ethernet (14) + IP starts at 14
        self.assertEqual(len(pkt) > 40, True)
        # EtherType = 0x0800 (IPv4) at bytes 12-13
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x0800)

    def test_vlan_tag_inserted(self):
        pkt = _build_with_encap(VLANEncap(vid=100, pcp=3, dei=0))
        # EtherType at 12 should be 0x8100 (VLAN)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)
        # TCI: pcp(3) << 13 | dei(0) << 12 | vid(100)
        tci = struct.unpack_from("!H", pkt, 14)[0]
        self.assertEqual(tci >> 13, 3)       # pcp
        self.assertEqual((tci >> 12) & 1, 0) # dei
        self.assertEqual(tci & 0x0FFF, 100)  # vid
        # Inner EtherType = IPv4
        self.assertEqual(struct.unpack_from("!H", pkt, 16)[0], 0x0800)

    def test_qinq_two_vlan_tags(self):
        pkt = _build_with_encap(QinQEncap(outer_vid=100, inner_vid=200))
        # Outer tag EtherType = 0x8100
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)
        # Inner tag EtherType = 0x8100
        self.assertEqual(struct.unpack_from("!H", pkt, 16)[0], 0x8100)
        outer_vid = struct.unpack_from("!H", pkt, 14)[0] & 0x0FFF
        inner_vid = struct.unpack_from("!H", pkt, 18)[0] & 0x0FFF
        self.assertEqual(outer_vid, 100)
        self.assertEqual(inner_vid, 200)

    def test_mpls_label_inserted(self):
        pkt = _build_with_encap(MPLSEncap(labels=[100]))
        # EtherType = 0x8847 (MPLS unicast)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8847)

    def test_mpls_two_labels(self):
        pkt = _build_with_encap(MPLSEncap(labels=[100, 200]))
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8847)
        # Bottom-of-stack bit on second label
        label2_entry = struct.unpack_from("!I", pkt, 14 + 4)[0]
        self.assertEqual(label2_entry & 0x100, 0x100)  # S=1

    def test_pppoe_session_frame(self):
        pkt = _build_with_encap(PPPoEEncap(session_id=0x1234))
        # EtherType = 0x8864 (PPPoE session)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8864)

    def test_gre_outer_ip_present(self):
        pkt = _build_with_encap(GREEncap(
            src_ip="203.0.113.1", dst_ip="203.0.113.2"))
        # Ethernet + IP: version/IHL at 14
        version = (pkt[14] >> 4)
        self.assertEqual(version, 4)
        # IP protocol at offset 23 should be 47 (GRE)
        self.assertEqual(pkt[23], 47)

    def test_gre_with_key(self):
        pkt = _build_with_encap(GREEncap(
            src_ip="203.0.113.1", dst_ip="203.0.113.2", key=0xDEAD))
        # GRE header starts at 14+20 = 34; flags at 34 should have Key Present bit
        gre_flags = struct.unpack_from("!H", pkt, 34)[0]
        self.assertTrue(gre_flags & 0x2000)  # Key Present flag

    def test_etherip_outer_ip_protocol_97(self):
        pkt = _build_with_encap(EtherIPEncap(
            src_ip="203.0.113.1", dst_ip="203.0.113.2"))
        # protocol = 97 (EtherIP) at byte 23
        self.assertEqual(pkt[23], 97)

    def test_ipip_outer_ip_protocol_4(self):
        pkt = _build_with_encap(IPIPEncap(
            src_ip="203.0.113.1", dst_ip="203.0.113.2"))
        # Outer IP protocol = 4 (IP-in-IP)
        self.assertEqual(pkt[23], 4)

    def test_combined_vlan_then_gre(self):
        layers = [VLANEncap(vid=100), GREEncap("203.0.113.1", "203.0.113.2")]
        pkt = _build_with_encap(layers)
        # Outer EtherType = 0x8100 (VLAN)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)
        # After VLAN tag (4 bytes), inner EtherType = 0x0800 (IPv4 — outer IP)
        self.assertEqual(struct.unpack_from("!H", pkt, 16)[0], 0x0800)
        # Outer IP proto = 47 (GRE) at eth+vlan+ip_offset = 14+4+9 = 27
        self.assertEqual(pkt[27], 47)

    def test_combined_mpls_then_ipip(self):
        layers = [MPLSEncap(labels=[100]), IPIPEncap("203.0.113.1", "203.0.113.2")]
        pkt = _build_with_encap(layers)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8847)
        # Outer IP starts at 14+4=18; proto at +9 = 27
        self.assertEqual(pkt[27], 4)  # IP-in-IP

    def test_list_encap_accepted(self):
        # A plain list is valid EncapSpec
        layers = [VLANEncap(vid=50)]
        pkt = _build_with_encap(layers)
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)


# ── Stream integration — each encap type ─────────────────────────────────────

class TestTCPStreamWithEncap(unittest.TestCase):

    def _stream(self, encap, **kw):
        return generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3, encap=encap, **kw
        )

    def test_no_encap_produces_packets(self):
        s = self._stream(None)
        self.assertGreater(len(s.packets), 0)

    def test_vlan_stream_packets_larger(self):
        plain = self._stream(None)
        vlan  = self._stream(VLANEncap(vid=100))
        # Each VLAN packet should be 4 bytes longer
        self.assertEqual(
            len(vlan.packets[0].raw) - len(plain.packets[0].raw), 4
        )

    def test_qinq_stream_packets_8_bytes_larger(self):
        plain = self._stream(None)
        qinq  = self._stream(QinQEncap(outer_vid=100, inner_vid=200))
        self.assertEqual(
            len(qinq.packets[0].raw) - len(plain.packets[0].raw), 8
        )

    def test_mpls_stream_has_mpls_ethertype(self):
        s = self._stream(MPLSEncap(labels=[100, 200]))
        pkt = s.packets[0].raw
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8847)

    def test_pppoe_stream_has_pppoe_ethertype(self):
        s = self._stream(PPPoEEncap(session_id=1))
        pkt = s.packets[0].raw
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8864)

    def test_gre_stream_outer_ip_is_tunnel(self):
        s = self._stream(GREEncap(src_ip="192.168.1.1", dst_ip="192.168.1.2"))
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 47)  # outer IP protocol = GRE

    def test_etherip_stream(self):
        s = self._stream(EtherIPEncap(src_ip="192.168.1.1", dst_ip="192.168.1.2"))
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 97)  # EtherIP

    def test_ipip_stream(self):
        s = self._stream(IPIPEncap(src_ip="192.168.1.1", dst_ip="192.168.1.2"))
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 4)  # IP-in-IP

    def test_combined_mpls_ipip_stream(self):
        layers = [MPLSEncap(labels=[100]), IPIPEncap("192.168.1.1", "192.168.1.2")]
        s = self._stream(layers)
        pkt = s.packets[0].raw
        # MPLS ethertype
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8847)

    def test_gre_stream_ipv6_inner(self):
        s = generate_tcp_stream(
            client_ip="2001:db8::1", server_ip="2001:db8::2",
            num_data_packets=2,
            encap=GREEncap(src_ip="192.168.1.1", dst_ip="192.168.1.2"),
        )
        self.assertGreater(len(s.packets), 0)

    def test_stream_list_encap(self):
        # Pass list instead of single value
        s = self._stream([VLANEncap(vid=10)])
        pkt = s.packets[0].raw
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)


class TestUDPStreamWithEncap(unittest.TestCase):

    def test_vlan_udp_stream(self):
        s = generate_udp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3, encap=VLANEncap(vid=200),
        )
        pkt = s.packets[0].raw
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)

    def test_gre_udp_stream(self):
        s = generate_udp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3,
            encap=GREEncap(src_ip="1.2.3.4", dst_ip="5.6.7.8"),
        )
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 47)

    def test_ipip_udp_stream(self):
        s = generate_udp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=2,
            encap=IPIPEncap(src_ip="1.2.3.4", dst_ip="5.6.7.8"),
        )
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 4)


class TestSCTPStreamWithEncap(unittest.TestCase):

    def test_vlan_sctp_stream(self):
        s = generate_sctp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=2, encap=VLANEncap(vid=100),
        )
        pkt = s.packets[0].raw
        self.assertEqual(struct.unpack_from("!H", pkt, 12)[0], 0x8100)

    def test_gre_sctp_stream(self):
        s = generate_sctp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=2,
            encap=GREEncap(src_ip="1.2.3.4", dst_ip="5.6.7.8"),
        )
        pkt = s.packets[0].raw
        self.assertEqual(pkt[23], 47)


# ── Fragmentation with encap ──────────────────────────────────────────────────

class TestFragmentationWithEncap(unittest.TestCase):
    """Ensure mtu fragmentation works correctly with encap layers."""

    def _frag_labels(self, stream) -> list[str]:
        return [p.label for p in stream.packets if "FRAG" in p.label]

    def test_vlan_fragmentation_produces_frags(self):
        s = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3,
            min_payload=800, max_payload=800,
            encap=VLANEncap(vid=100),
            mtu=500,
        )
        frags = self._frag_labels(s)
        self.assertGreater(len(frags), 0)

    def test_vlan_frag_packets_have_correct_ethertype(self):
        s = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3,
            min_payload=800, max_payload=800,
            encap=VLANEncap(vid=100),
            mtu=500,
        )
        for pkt in s.packets:
            if "FRAG" in pkt.label:
                self.assertEqual(struct.unpack_from("!H", pkt.raw, 12)[0], 0x8100)

    def test_gre_fragmentation(self):
        s = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3,
            min_payload=1400, max_payload=1400,
            encap=GREEncap(src_ip="1.2.3.4", dst_ip="5.6.7.8"),
            mtu=500,
        )
        frags = self._frag_labels(s)
        self.assertGreater(len(frags), 0)

    def test_pppoe_fragmentation_updates_pppoe_length(self):
        s = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=3,
            min_payload=800, max_payload=800,
            encap=PPPoEEncap(session_id=1),
            mtu=500,
        )
        for pkt in s.packets:
            if "FRAG" not in pkt.label:
                continue
            raw = pkt.raw
            # PPPoE header starts at offset 14 (after eth)
            # PPPoE ver/type=0x11 at byte 14
            self.assertEqual(raw[14], 0x11)
            pppoe_len = struct.unpack_from("!H", raw, 18)[0]
            # IP fragment starts at offset 22 (14 eth + 8 pppoe)
            ip_frag_bytes = raw[22:]
            self.assertEqual(pppoe_len, 2 + len(ip_frag_bytes))

    def test_ipip_fragmentation(self):
        s = generate_udp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=5,
            min_payload=1400, max_payload=1400,
            encap=IPIPEncap(src_ip="1.2.3.4", dst_ip="5.6.7.8"),
            mtu=400,
        )
        frags = self._frag_labels(s)
        self.assertGreater(len(frags), 0)


if __name__ == "__main__":
    unittest.main()
