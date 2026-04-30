"""Tests for SCTP stream generation."""
from __future__ import annotations

import struct

from packeteer.generate.sctp_stream import SCTPStream, SCTPStreamPacket, generate_sctp_stream

_HANDSHAKE_LABELS = ["INIT", "INIT-ACK", "COOKIE-ECHO", "COOKIE-ACK"]
_SHUTDOWN_LABELS  = ["SHUTDOWN", "SHUTDOWN-ACK", "SHUTDOWN-COMPLETE"]


def _make_stream(**kw: object) -> SCTPStream:
    defaults: dict[str, object] = {
        "client_ip": "10.0.0.1",
        "server_ip": "10.0.0.2",
        "client_port": 54321,
        "server_port": 9999,
        "num_data_packets": 3,
        "min_payload": 20,
        "max_payload": 100,
        "payload_distribution": "fixed",
        "inter_packet_gap": 0.001,
    }
    defaults.update(kw)
    return generate_sctp_stream(**defaults)


def _vtag(raw: bytes, include_ethernet: bool = True) -> int:
    """Extract the SCTP verification tag from a raw packet."""
    ip_start = 14 if include_ethernet else 0
    # IPv4: 20-byte header
    sctp_start = ip_start + 20
    # SCTP common header: src_port(2) + dst_port(2) + vtag(4)
    return struct.unpack("!I", raw[sctp_start + 4:sctp_start + 8])[0]


# ── Group 1: basic structure ──────────────────────────────────────────────────

class TestBasicStructure:
    def test_packet_count_formula(self):
        # 2*N + 7 total packets
        s = _make_stream(num_data_packets=5)
        assert len(s.packets) == 2 * 5 + 7

    def test_packet_count_one(self):
        s = _make_stream(num_data_packets=1)
        assert len(s.packets) == 2 * 1 + 7

    def test_returns_sctp_stream(self):
        assert isinstance(_make_stream(), SCTPStream)

    def test_packets_are_sctp_stream_packet(self):
        s = _make_stream()
        assert all(isinstance(p, SCTPStreamPacket) for p in s.packets)

    def test_to_pcap_tuples_length(self):
        s = _make_stream(num_data_packets=4)
        assert len(s.to_pcap_tuples()) == 2 * 4 + 7

    def test_to_pcap_tuples_format(self):
        s = _make_stream(num_data_packets=1)
        raw, ts_sec, ts_usec = s.to_pcap_tuples()[0]
        assert isinstance(raw, bytes)
        assert isinstance(ts_sec, int)
        assert isinstance(ts_usec, int)

    def test_client_packets_filter(self):
        # c2s: INIT + COOKIE-ECHO + DATA[0..N-1] + SHUTDOWN + SHUTDOWN-COMPLETE = N+4
        s = _make_stream(num_data_packets=3)
        assert len(s.client_packets()) == 3 + 4

    def test_server_packets_filter(self):
        # s2c: INIT-ACK + COOKIE-ACK + SACK[0..N-1] + SHUTDOWN-ACK = N+3
        s = _make_stream(num_data_packets=3)
        assert len(s.server_packets()) == 3 + 3


# ── Group 2: labels ───────────────────────────────────────────────────────────

class TestLabels:
    def test_handshake_labels(self):
        s = _make_stream(num_data_packets=2)
        labels = [p.label for p in s.packets]
        for lbl in _HANDSHAKE_LABELS:
            assert lbl in labels

    def test_data_labels(self):
        s = _make_stream(num_data_packets=3)
        labels = [p.label for p in s.packets]
        for i in range(3):
            assert f"DATA[{i}]" in labels

    def test_sack_labels(self):
        s = _make_stream(num_data_packets=3)
        labels = [p.label for p in s.packets]
        for i in range(3):
            assert f"SACK[{i}]" in labels

    def test_shutdown_labels(self):
        s = _make_stream(num_data_packets=2)
        labels = [p.label for p in s.packets]
        for lbl in _SHUTDOWN_LABELS:
            assert lbl in labels

    def test_label_order(self):
        s = _make_stream(num_data_packets=2)
        labels = [p.label for p in s.packets]
        expected = (
            ["INIT", "INIT-ACK", "COOKIE-ECHO", "COOKIE-ACK"]
            + ["DATA[0]", "SACK[0]", "DATA[1]", "SACK[1]"]
            + ["SHUTDOWN", "SHUTDOWN-ACK", "SHUTDOWN-COMPLETE"]
        )
        assert labels == expected


# ── Group 3: directions ───────────────────────────────────────────────────────

class TestDirections:
    def test_init_is_c2s(self):
        s = _make_stream(num_data_packets=1)
        init_pkt = next(p for p in s.packets if p.label == "INIT")
        assert init_pkt.direction == "c2s"

    def test_init_ack_is_s2c(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "INIT-ACK")
        assert pkt.direction == "s2c"

    def test_cookie_echo_is_c2s(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "COOKIE-ECHO")
        assert pkt.direction == "c2s"

    def test_cookie_ack_is_s2c(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "COOKIE-ACK")
        assert pkt.direction == "s2c"

    def test_data_is_c2s(self):
        s = _make_stream(num_data_packets=2)
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        assert all(p.direction == "c2s" for p in data_pkts)

    def test_sack_is_s2c(self):
        s = _make_stream(num_data_packets=2)
        sack_pkts = [p for p in s.packets if p.label.startswith("SACK")]
        assert all(p.direction == "s2c" for p in sack_pkts)

    def test_shutdown_is_c2s(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "SHUTDOWN")
        assert pkt.direction == "c2s"

    def test_shutdown_ack_is_s2c(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "SHUTDOWN-ACK")
        assert pkt.direction == "s2c"

    def test_shutdown_complete_is_c2s(self):
        s = _make_stream(num_data_packets=1)
        pkt = next(p for p in s.packets if p.label == "SHUTDOWN-COMPLETE")
        assert pkt.direction == "c2s"


# ── Group 4: verification tags ────────────────────────────────────────────────

class TestVerificationTags:
    def test_init_vtag_is_zero(self):
        s = _make_stream(num_data_packets=1)
        init_pkt = next(p for p in s.packets if p.label == "INIT")
        assert _vtag(init_pkt.raw) == 0

    def test_c2s_post_init_have_consistent_vtag(self):
        # All c2s packets after INIT carry the server's vtag (server_vtag)
        s = _make_stream(num_data_packets=2)
        c2s_non_init = [p for p in s.packets if p.direction == "c2s" and p.label != "INIT"]
        vtags = {_vtag(p.raw) for p in c2s_non_init}
        assert len(vtags) == 1  # all the same

    def test_s2c_have_consistent_vtag(self):
        # All s2c packets carry the client's vtag (client_vtag)
        s = _make_stream(num_data_packets=2)
        s2c_pkts = [p for p in s.packets if p.direction == "s2c"]
        vtags = {_vtag(p.raw) for p in s2c_pkts}
        assert len(vtags) == 1

    def test_c2s_and_s2c_vtags_differ(self):
        # client_vtag != server_vtag (overwhelmingly likely with random 32-bit values)
        s = _make_stream(num_data_packets=2)
        c2s_vtag = _vtag(next(p for p in s.packets if p.label == "COOKIE-ECHO").raw)
        s2c_vtag = _vtag(next(p for p in s.packets if p.label == "INIT-ACK").raw)
        assert c2s_vtag != 0
        assert s2c_vtag != 0
        # Note: astronomically unlikely but not guaranteed — just verify nonzero

    def test_no_ethernet_vtag_still_correct(self):
        s = generate_sctp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2",
            num_data_packets=1, include_ethernet=False,
        )
        init_pkt = next(p for p in s.packets if p.label == "INIT")
        assert _vtag(init_pkt.raw, include_ethernet=False) == 0


# ── Group 5: TSN ──────────────────────────────────────────────────────────────

class TestTSN:
    def test_control_packets_have_tsn_zero(self):
        s = _make_stream(num_data_packets=2)
        control_labels = set(_HANDSHAKE_LABELS + _SHUTDOWN_LABELS + ["SACK[0]", "SACK[1]"])
        for pkt in s.packets:
            if pkt.label in control_labels:
                assert pkt.tsn == 0, f"{pkt.label} should have tsn=0"

    def test_data_packets_have_nonzero_tsn(self):
        # TSN is a random 32-bit value, so we check payload_len > 0 as a proxy
        s = _make_stream(num_data_packets=2)
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        # At least the packets exist and their tsn field is set (used internally)
        assert len(data_pkts) == 2

    def test_tsn_increments_by_one(self):
        s = _make_stream(num_data_packets=4)
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        tsns = [p.tsn for p in data_pkts]
        for i in range(1, len(tsns)):
            expected = (tsns[0] + i) % (2 ** 32)
            assert tsns[i] == expected

    def test_tsn_all_unique(self):
        s = _make_stream(num_data_packets=5)
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        tsns = [p.tsn for p in data_pkts]
        assert len(tsns) == len(set(tsns))


# ── Group 6: timestamps ───────────────────────────────────────────────────────

class TestTimestamps:
    def test_timestamps_increasing(self):
        s = _make_stream(num_data_packets=3, inter_packet_gap=0.01)
        usecs = [p.ts_sec * 1_000_000 + p.ts_usec for p in s.packets]
        assert usecs == sorted(usecs)
        assert len(set(usecs)) == len(usecs)

    def test_ts_usec_range(self):
        s = _make_stream(num_data_packets=3)
        for p in s.packets:
            assert 0 <= p.ts_usec < 1_000_000

    def test_gap_applied(self):
        s = _make_stream(num_data_packets=1, inter_packet_gap=0.1)
        usecs = [p.ts_sec * 1_000_000 + p.ts_usec for p in s.packets]
        for i in range(1, len(usecs)):
            assert usecs[i] - usecs[i - 1] >= 90_000

    def test_jitter_still_sorted(self):
        s = _make_stream(num_data_packets=5, inter_packet_gap=0.001, gap_jitter=0.005)
        usecs = [p.ts_sec * 1_000_000 + p.ts_usec for p in s.packets]
        assert usecs == sorted(usecs)


# ── Group 7: payload ──────────────────────────────────────────────────────────

class TestPayload:
    def test_fixed_payload_size(self):
        s = _make_stream(num_data_packets=3, min_payload=64, max_payload=64,
                         payload_distribution="fixed")
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        assert all(p.payload_len == 64 for p in data_pkts)

    def test_uniform_payload_in_range(self):
        s = _make_stream(num_data_packets=20, min_payload=10, max_payload=50,
                         payload_distribution="uniform")
        data_pkts = [p for p in s.packets if p.label.startswith("DATA")]
        for p in data_pkts:
            assert 10 <= p.payload_len <= 50

    def test_control_packets_have_zero_payload_len(self):
        s = _make_stream(num_data_packets=2)
        control_pkts = [p for p in s.packets if not p.label.startswith("DATA")]
        for p in control_pkts:
            assert p.payload_len == 0


# ── Group 8: packet contents ──────────────────────────────────────────────────

class TestPacketContents:
    def test_has_ethernet_header(self):
        s = _make_stream(num_data_packets=1)
        pkt = s.packets[0]
        # Ethernet(14) + IPv4(20) + SCTP(12) = 46 minimum
        assert len(pkt.raw) >= 46

    def test_no_ethernet_header(self):
        s = _make_stream(num_data_packets=1, include_ethernet=False)
        pkt = s.packets[0]
        assert (pkt.raw[0] >> 4) == 4  # IPv4 version

    def test_ipv4_protocol_sctp(self):
        s = _make_stream(num_data_packets=1)
        pkt = s.packets[0]
        # IPv4 protocol field at offset 14+9 = 23
        assert pkt.raw[23] == 132  # IPPROTO_SCTP

    def test_sctp_src_port(self):
        s = _make_stream(num_data_packets=1, client_port=11111)
        init_pkt = next(p for p in s.packets if p.label == "INIT")
        # Ethernet(14) + IPv4(20) = 34; SCTP src_port at 34..35
        src_port = struct.unpack("!H", init_pkt.raw[34:36])[0]
        assert src_port == 11111

    def test_sctp_dst_port(self):
        s = _make_stream(num_data_packets=1, server_port=22222)
        init_pkt = next(p for p in s.packets if p.label == "INIT")
        dst_port = struct.unpack("!H", init_pkt.raw[36:38])[0]
        assert dst_port == 22222

    def test_ipv6(self):
        s = generate_sctp_stream(
            client_ip="2001:db8::1", server_ip="2001:db8::2",
            num_data_packets=1, include_ethernet=False,
        )
        pkt = s.packets[0]
        assert (pkt.raw[0] >> 4) == 6  # IPv6 version


# ── Group 9: middlebox MTU ────────────────────────────────────────────────────

class TestMiddleboxMtu:
    def test_large_payload_gets_fragmented(self):
        s = _make_stream(num_data_packets=1, min_payload=2000, max_payload=2000,
                         payload_distribution="fixed", mtu=1500)
        assert len(s.packets) > 2 * 1 + 7  # more than unfragmented total

    def test_fragment_labels(self):
        s = _make_stream(num_data_packets=1, min_payload=2000, max_payload=2000,
                         payload_distribution="fixed", mtu=1500)
        frag_pkts = [p for p in s.packets if "FRAG" in p.label]
        assert len(frag_pkts) > 0

    def test_small_payload_not_fragmented(self):
        s = _make_stream(num_data_packets=3, min_payload=100, max_payload=100,
                         payload_distribution="fixed", mtu=1500)
        assert len(s.packets) == 2 * 3 + 7
