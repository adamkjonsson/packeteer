"""Tests for UDP stream generation."""
from __future__ import annotations

import struct
import pytest

from packeteer.generator.udp_stream import generate_udp_stream, UDPStream, UDPStreamPacket


def _make_stream(**kw) -> UDPStream:
    defaults = dict(
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        client_port=54321,
        server_port=53,
        num_data_packets=5,
        min_payload=20,
        max_payload=100,
        payload_distribution="fixed",
        inter_packet_gap=0.001,
    )
    defaults.update(kw)
    return generate_udp_stream(**defaults)


# ── Group 1: basic structure ──────────────────────────────────────────────────

class TestBasicStructure:
    def test_packet_count(self):
        s = _make_stream(num_data_packets=7)
        assert len(s.packets) == 7

    def test_returns_udp_stream(self):
        assert isinstance(_make_stream(), UDPStream)

    def test_packets_are_udp_stream_packet(self):
        s = _make_stream()
        assert all(isinstance(p, UDPStreamPacket) for p in s.packets)

    def test_all_c2s(self):
        s = _make_stream()
        assert all(p.direction == "c2s" for p in s.packets)

    def test_labels(self):
        s = _make_stream(num_data_packets=3)
        labels = [p.label for p in s.packets]
        assert labels == ["DATA[0]", "DATA[1]", "DATA[2]"]

    def test_to_pcap_tuples_length(self):
        s = _make_stream(num_data_packets=4)
        tuples = s.to_pcap_tuples()
        assert len(tuples) == 4

    def test_to_pcap_tuples_format(self):
        s = _make_stream(num_data_packets=1)
        raw, ts_sec, ts_usec = s.to_pcap_tuples()[0]
        assert isinstance(raw, bytes)
        assert isinstance(ts_sec, int)
        assert isinstance(ts_usec, int)

    def test_client_packets_filter(self):
        s = _make_stream(num_data_packets=3)
        assert len(s.client_packets()) == 3

    def test_server_packets_filter(self):
        s = _make_stream(num_data_packets=3)
        assert len(s.server_packets()) == 0


# ── Group 2: packet contents ──────────────────────────────────────────────────

class TestPacketContents:
    def test_has_ethernet_header(self):
        s = _make_stream(num_data_packets=1)
        pkt = s.packets[0]
        # Ethernet + IPv4 + UDP = 14+20+8 = 42
        assert len(pkt.raw) >= 42

    def test_no_ethernet_header(self):
        s = _make_stream(num_data_packets=1, include_ethernet=False)
        pkt = s.packets[0]
        # IPv4 + UDP = 20+8 = 28
        assert len(pkt.raw) >= 28
        # First byte should be IPv4 (0x45) not Ethernet
        assert (pkt.raw[0] >> 4) == 4

    def test_ipv4_protocol_udp(self):
        s = _make_stream(num_data_packets=1)
        pkt = s.packets[0]
        # IPv4 protocol field at offset 14+9 = 23
        assert pkt.raw[23] == 17  # IPPROTO_UDP

    def test_udp_dst_port(self):
        s = _make_stream(num_data_packets=1, server_port=5353)
        pkt = s.packets[0]
        dst_port = struct.unpack("!H", pkt.raw[14 + 20 + 2:14 + 20 + 4])[0]
        assert dst_port == 5353

    def test_udp_src_port(self):
        s = _make_stream(num_data_packets=1, client_port=9999)
        pkt = s.packets[0]
        src_port = struct.unpack("!H", pkt.raw[14 + 20:14 + 20 + 2])[0]
        assert src_port == 9999

    def test_payload_len_field(self):
        s = _make_stream(num_data_packets=1, min_payload=50, max_payload=50)
        pkt = s.packets[0]
        assert pkt.payload_len == 50

    def test_ipv6(self):
        s = generate_udp_stream(
            client_ip="2001:db8::1", server_ip="2001:db8::2",
            num_data_packets=1, include_ethernet=False,
        )
        pkt = s.packets[0]
        assert (pkt.raw[0] >> 4) == 6  # IPv6 version


# ── Group 3: timestamps ───────────────────────────────────────────────────────

class TestTimestamps:
    def test_timestamps_increasing(self):
        s = _make_stream(num_data_packets=5, inter_packet_gap=0.01)
        usecs = [p.ts_sec * 1_000_000 + p.ts_usec for p in s.packets]
        assert usecs == sorted(usecs)
        assert len(set(usecs)) == len(usecs)  # all unique

    def test_ts_usec_range(self):
        s = _make_stream(num_data_packets=5)
        for p in s.packets:
            assert 0 <= p.ts_usec < 1_000_000

    def test_gap_applied(self):
        s = _make_stream(num_data_packets=2, inter_packet_gap=0.1)
        p0_us = s.packets[0].ts_sec * 1_000_000 + s.packets[0].ts_usec
        p1_us = s.packets[1].ts_sec * 1_000_000 + s.packets[1].ts_usec
        assert p1_us - p0_us >= 90_000  # at least 90 ms

    def test_jitter_still_sorted(self):
        s = _make_stream(num_data_packets=10, inter_packet_gap=0.001, gap_jitter=0.005)
        usecs = [p.ts_sec * 1_000_000 + p.ts_usec for p in s.packets]
        assert usecs == sorted(usecs)


# ── Group 4: payload ──────────────────────────────────────────────────────────

class TestPayload:
    def test_fixed_payload_size(self):
        s = _make_stream(num_data_packets=3, min_payload=64, max_payload=64,
                         payload_distribution="fixed")
        for p in s.packets:
            assert p.payload_len == 64

    def test_uniform_payload_in_range(self):
        s = _make_stream(num_data_packets=20, min_payload=10, max_payload=50,
                         payload_distribution="uniform")
        for p in s.packets:
            assert 10 <= p.payload_len <= 50

    def test_continuous_payload_no_restart(self):
        # All packets share one rolling window of default_payload.txt
        s = _make_stream(num_data_packets=2, min_payload=4, max_payload=4,
                         payload_distribution="fixed", include_ethernet=False)
        # Extract payload from UDP: ip(20) + udp(8) = offset 28, length 4
        p0 = s.packets[0].raw[28:32]
        p1 = s.packets[1].raw[28:32]
        # They should be adjacent slices, not the same
        assert p0 != p1


# ── Group 5: middlebox MTU ────────────────────────────────────────────────────

class TestMiddleboxMtu:
    def test_large_payload_gets_fragmented(self):
        s = _make_stream(num_data_packets=1, min_payload=2000, max_payload=2000,
                         payload_distribution="fixed", mtu=1500)
        assert len(s.packets) > 1

    def test_fragment_labels(self):
        s = _make_stream(num_data_packets=1, min_payload=2000, max_payload=2000,
                         payload_distribution="fixed", mtu=1500)
        assert all("FRAG" in p.label for p in s.packets)

    def test_small_payload_not_fragmented(self):
        s = _make_stream(num_data_packets=3, min_payload=100, max_payload=100,
                         payload_distribution="fixed", mtu=1500)
        assert len(s.packets) == 3
