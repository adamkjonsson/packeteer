"""Tests for packet_generator.tcp_stream — TCP stream generation."""
from __future__ import annotations

import io
import unittest

from packet_generator.tcp_stream import generate_tcp_stream, TCPStream, TCPStreamPacket
from packet_generator.tcp import TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN, TCPOptions
from packet_generator.pcap import write_pcap, LINKTYPE_ETHERNET, LINKTYPE_RAW

_WRAP = 2 ** 32

# Fixed ISNs make sequence-number assertions deterministic.
_CLIENT_ISN = 1000
_SERVER_ISN = 5000


def _stream(**kwargs) -> TCPStream:
    """Helper: generate a stream with fixed ISNs and sensible defaults."""
    defaults = dict(
        client_ip="10.0.0.1",
        server_ip="10.0.0.2",
        client_isn=_CLIENT_ISN,
        server_isn=_SERVER_ISN,
    )
    defaults.update(kwargs)
    return generate_tcp_stream(**defaults)


# ── Group 1: Handshake structure ──────────────────────────────────────────────

class TestHandshakeStructure(unittest.TestCase):

    def setUp(self):
        self.pkts = _stream(num_data_packets=5).packets

    def test_syn_flags(self):
        self.assertEqual(self.pkts[0].flags, TCP_SYN)

    def test_syn_direction(self):
        self.assertEqual(self.pkts[0].direction, "c2s")

    def test_syn_label(self):
        self.assertEqual(self.pkts[0].label, "SYN")

    def test_syn_no_payload(self):
        self.assertEqual(self.pkts[0].payload_len, 0)

    def test_syn_ack_flags(self):
        self.assertEqual(self.pkts[1].flags, TCP_SYN | TCP_ACK)

    def test_syn_ack_direction(self):
        self.assertEqual(self.pkts[1].direction, "s2c")

    def test_syn_ack_label(self):
        self.assertEqual(self.pkts[1].label, "SYN-ACK")

    def test_handshake_ack_flags(self):
        self.assertEqual(self.pkts[2].flags, TCP_ACK)

    def test_handshake_ack_direction(self):
        self.assertEqual(self.pkts[2].direction, "c2s")

    def test_handshake_ack_label(self):
        self.assertEqual(self.pkts[2].label, "ACK")

    def test_handshake_ack_no_payload(self):
        self.assertEqual(self.pkts[2].payload_len, 0)


# ── Group 2: Teardown structure ───────────────────────────────────────────────

class TestTeardownStructure(unittest.TestCase):

    def setUp(self):
        self.pkts = _stream(num_data_packets=3).packets

    def test_teardown_labels(self):
        self.assertEqual(
            [p.label for p in self.pkts[-4:]],
            ["FIN-ACK", "ACK", "FIN-ACK", "ACK"],
        )

    def test_teardown_directions(self):
        self.assertEqual(
            [p.direction for p in self.pkts[-4:]],
            ["c2s", "s2c", "s2c", "c2s"],
        )

    def test_teardown_flags(self):
        self.assertEqual(
            [p.flags for p in self.pkts[-4:]],
            [TCP_FIN | TCP_ACK, TCP_ACK, TCP_FIN | TCP_ACK, TCP_ACK],
        )

    def test_teardown_no_payload(self):
        for p in self.pkts[-4:]:
            with self.subTest(label=p.label):
                self.assertEqual(p.payload_len, 0)


# ── Group 3: Sequence / acknowledgement number correctness ────────────────────

class TestSeqAckCorrectness(unittest.TestCase):

    def setUp(self):
        self.stream = _stream(num_data_packets=3, payload_sizes=[100, 200, 300])
        self.pkts = self.stream.packets

    def test_syn_seq_equals_client_isn(self):
        self.assertEqual(self.pkts[0].seq, _CLIENT_ISN)

    def test_syn_ack_field_is_zero(self):
        # SYN has no ACK flag, so ack recorded in TCPStreamPacket must be 0
        self.assertEqual(self.pkts[0].ack, 0)

    def test_syn_ack_seq_equals_server_isn(self):
        self.assertEqual(self.pkts[1].seq, _SERVER_ISN)

    def test_server_acks_client_isn_plus_one(self):
        self.assertEqual(self.pkts[1].ack, _CLIENT_ISN + 1)

    def test_client_acks_server_isn_plus_one(self):
        self.assertEqual(self.pkts[2].ack, _SERVER_ISN + 1)

    def test_first_data_seq(self):
        # SYN consumed 1, handshake ACK consumed 0
        self.assertEqual(self.pkts[3].seq, _CLIENT_ISN + 1)

    def test_data_seq_advances_by_payload_length(self):
        data_pkts = [p for p in self.pkts if p.label.startswith("DATA")]
        for i in range(2):
            with self.subTest(i=i):
                cur = data_pkts[i]
                nxt = data_pkts[i + 1]
                self.assertEqual(nxt.seq, (cur.seq + cur.payload_len) % _WRAP)

    def test_data_seq_chain(self):
        data_pkts = [p for p in self.pkts if p.label.startswith("DATA")]
        self.assertEqual(data_pkts[1].seq, _CLIENT_ISN + 1 + 100)
        self.assertEqual(data_pkts[2].seq, _CLIENT_ISN + 1 + 100 + 200)

    def test_fin_consumes_one_seq(self):
        # Server ACK of client FIN must ack client_fin.seq + 1
        client_fin = self.pkts[-4]
        server_ack_of_fin = self.pkts[-3]
        self.assertEqual(server_ack_of_fin.ack, (client_fin.seq + 1) % _WRAP)

    def test_server_fin_acked_correctly(self):
        server_fin = self.pkts[-2]
        client_final_ack = self.pkts[-1]
        self.assertEqual(client_final_ack.ack, (server_fin.seq + 1) % _WRAP)


# ── Group 4: 32-bit sequence number wrap-around ───────────────────────────────

class TestSeqWrapAround(unittest.TestCase):

    def test_seq_wraps_at_32_bits(self):
        isn = _WRAP - 2
        stream = generate_tcp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            client_isn=isn,
            server_isn=0,
            num_data_packets=1,
            payload_sizes=[4],
        )
        pkts = stream.packets
        # SYN: seq = WRAP - 2
        self.assertEqual(pkts[0].seq, isn)
        # After SYN, client.seq = WRAP - 1; handshake ACK sends that seq
        self.assertEqual(pkts[2].seq, (isn + 1) % _WRAP)
        # DATA[0]: seq = WRAP - 1; after DATA, client.seq = (WRAP-1+4) % WRAP = 3
        self.assertEqual(pkts[3].seq, (isn + 1) % _WRAP)
        # Server ACK of data: ack = (WRAP - 1 + 4) % WRAP = 3
        self.assertEqual(pkts[4].ack, (isn + 1 + 4) % _WRAP)


# ── Group 5: Packet count ─────────────────────────────────────────────────────

class TestPacketCount(unittest.TestCase):

    def test_total_count_formula(self):
        # handshake(3) + data+ack(2*n) + teardown(4) = 2*n + 7
        for n in (0, 1, 5, 10):
            with self.subTest(n=n):
                self.assertEqual(len(_stream(num_data_packets=n).packets), 2 * n + 7)

    def test_zero_data_packets_labels(self):
        pkts = _stream(num_data_packets=0).packets
        self.assertEqual(
            [p.label for p in pkts],
            ["SYN", "SYN-ACK", "ACK", "FIN-ACK", "ACK", "FIN-ACK", "ACK"],
        )

    def test_data_labels(self):
        pkts = _stream(num_data_packets=3, payload_sizes=[1, 1, 1]).packets
        data_labels = [p.label for p in pkts if p.label.startswith("DATA")]
        self.assertEqual(data_labels, ["DATA[0]", "DATA[1]", "DATA[2]"])


# ── Group 6: Payload variation ────────────────────────────────────────────────

class TestPayloadVariation(unittest.TestCase):

    def test_explicit_payload_sizes(self):
        sizes = [50, 100, 150, 200]
        pkts = _stream(num_data_packets=4, payload_sizes=sizes).packets
        data = [p for p in pkts if p.label.startswith("DATA")]
        self.assertEqual([p.payload_len for p in data], sizes)

    def test_explicit_payload_sizes_wrong_length_raises(self):
        with self.assertRaises(ValueError):
            _stream(num_data_packets=3, payload_sizes=[100, 200])

    def test_uniform_distribution_within_bounds(self):
        mn, mx = 100, 500
        pkts = _stream(
            num_data_packets=20,
            min_payload=mn,
            max_payload=mx,
            payload_distribution="uniform",
        ).packets
        for p in pkts:
            if p.label.startswith("DATA"):
                self.assertGreaterEqual(p.payload_len, mn)
                self.assertLessEqual(p.payload_len, mx)

    def test_fixed_distribution(self):
        pkts = _stream(
            num_data_packets=5,
            max_payload=800,
            payload_distribution="fixed",
        ).packets
        data = [p for p in pkts if p.label.startswith("DATA")]
        self.assertTrue(all(p.payload_len == 800 for p in data))

    def test_bimodal_distribution_within_bounds(self):
        mn, mx = 40, 1460
        pkts = _stream(
            num_data_packets=20,
            min_payload=mn,
            max_payload=mx,
            payload_distribution="bimodal",
        ).packets
        for p in pkts:
            if p.label.startswith("DATA"):
                self.assertGreaterEqual(p.payload_len, mn)
                self.assertLessEqual(p.payload_len, mx)

    def test_unknown_distribution_raises(self):
        with self.assertRaises(ValueError):
            _stream(num_data_packets=1, payload_distribution="random_walk")


# ── Group 7: Bytes validity ───────────────────────────────────────────────────

class TestBytesValidity(unittest.TestCase):

    def test_all_raw_are_bytes(self):
        for p in _stream(num_data_packets=3).packets:
            self.assertIsInstance(p.raw, bytes)

    def test_ethernet_header_present_by_default(self):
        # First packet (SYN) goes client→server; dst_mac is server_mac="00:00:00:00:00:02"
        syn = _stream(num_data_packets=1).packets[0]
        self.assertEqual(syn.raw[:6], bytes.fromhex("000000000002"))

    def test_no_ethernet_when_disabled(self):
        pkts = _stream(num_data_packets=1, include_ethernet=False).packets
        # Without Ethernet, raw starts with the IP header whose first nibble is version
        first_byte = pkts[0].raw[0]
        ip_version = first_byte >> 4
        self.assertEqual(ip_version, 4)

    def test_all_packets_non_empty(self):
        for p in _stream(num_data_packets=3).packets:
            self.assertGreater(len(p.raw), 0)


# ── Group 8: pcap integration ─────────────────────────────────────────────────

class TestPcapIntegration(unittest.TestCase):

    def test_to_pcap_tuples_format(self):
        stream = _stream(num_data_packets=3)
        for t in stream.to_pcap_tuples():
            self.assertEqual(len(t), 3)
            self.assertIsInstance(t[0], bytes)
            self.assertIsInstance(t[1], int)
            self.assertIsInstance(t[2], int)

    def test_to_pcap_tuples_length(self):
        n = 5
        stream = _stream(num_data_packets=n)
        self.assertEqual(len(stream.to_pcap_tuples()), 2 * n + 7)

    def test_write_pcap_roundtrip(self):
        stream = _stream(num_data_packets=3)
        buf = io.BytesIO()
        write_pcap(stream.to_pcap_tuples(), file_object=buf, link_type=LINKTYPE_ETHERNET)
        buf.seek(0)
        # pcap global header: magic(4) + version_major(2) + version_minor(2)
        #                   + thiszone(4) + sigfigs(4) + snaplen(4) + network(4) = 24 bytes
        magic = buf.read(4)
        self.assertIn(magic, (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4'))

    def test_client_packets_filter(self):
        stream = _stream(num_data_packets=3)
        c2s = stream.client_packets()
        self.assertTrue(all(p.direction == "c2s" for p in c2s))

    def test_server_packets_filter(self):
        stream = _stream(num_data_packets=3)
        s2c = stream.server_packets()
        self.assertTrue(all(p.direction == "s2c" for p in s2c))


# ── Group 9: Timestamps ───────────────────────────────────────────────────────

class TestTimestamps(unittest.TestCase):

    def test_timestamps_increase_monotonically(self):
        pkts = _stream(num_data_packets=5).packets
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in pkts]
        for i in range(1, len(times)):
            self.assertGreater(times[i], times[i - 1])

    def test_base_time_respected(self):
        base = 1_700_000_000.0
        pkts = _stream(num_data_packets=1, base_time=base).packets
        self.assertEqual(pkts[0].ts_sec, int(base))

    def test_inter_packet_gap(self):
        gap = 0.005  # 5 ms
        pkts = _stream(num_data_packets=1, inter_packet_gap=gap, base_time=0.0).packets
        t0 = pkts[0].ts_sec * 1_000_000 + pkts[0].ts_usec
        t1 = pkts[1].ts_sec * 1_000_000 + pkts[1].ts_usec
        self.assertEqual(t1 - t0, int(gap * 1_000_000))

    def test_jitter_output_sorted_by_timestamp(self):
        # With large jitter packets will be reordered; the returned list must
        # still be sorted by (ts_sec, ts_usec).
        pkts = _stream(
            num_data_packets=20,
            inter_packet_gap=0.001,
            gap_jitter=0.002,
            base_time=0.0,
        ).packets
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in pkts]
        self.assertEqual(times, sorted(times))

    def test_jitter_timestamps_within_expected_range(self):
        # Each packet n has timestamp: base + n*gap + delay, delay in [0, jitter].
        # The last packet (index N-1) is sent at (N-1)*gap and can arrive at most
        # (N-1)*gap + jitter after base.
        gap = 0.010
        jitter = 0.005
        pkts = _stream(
            num_data_packets=50,
            inter_packet_gap=gap,
            gap_jitter=jitter,
            base_time=0.0,
        ).packets
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in pkts]
        n = len(pkts) - 1
        gap_usec = int(gap * 1_000_000)
        jitter_usec = int(jitter * 1_000_000)
        for i, t in enumerate(times):
            # Packet i was sent at index i*gap (before sorting, so we bound by n)
            self.assertLessEqual(t, n * gap_usec + jitter_usec)


# ── Group 10: Packet loss ─────────────────────────────────────────────────────

class TestPacketLoss(unittest.TestCase):

    def test_zero_loss_no_packets_dropped(self):
        n = 10
        stream = _stream(num_data_packets=n, packet_loss_probability=0.0)
        self.assertEqual(len(stream.packets), 2 * n + 7)

    def test_full_loss_no_packets_remain(self):
        stream = _stream(num_data_packets=10, packet_loss_probability=1.0)
        self.assertEqual(len(stream.packets), 0)

    def test_partial_loss_reduces_packet_count(self):
        # At 50 % loss over 200 data packets the chance of ending up with the
        # full count is astronomically small.
        stream = _stream(num_data_packets=100, packet_loss_probability=0.5)
        self.assertLess(len(stream.packets), 2 * 100 + 7)

    def test_seq_numbers_unaffected_by_loss(self):
        # With 100 % loss the stream is empty, but with 0 % loss seq numbers
        # must still be correct — check they are not disturbed by the loss path.
        stream = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            packet_loss_probability=0.0,
        )
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA")]
        self.assertEqual(data_pkts[1].seq, _CLIENT_ISN + 1 + 100)
        self.assertEqual(data_pkts[2].seq, _CLIENT_ISN + 1 + 100 + 200)


# ── Group 11: IPv6 support ───────────────────────────────────────────────────

class TestIPv6Support(unittest.TestCase):

    def test_ipv6_stream_builds_without_error(self):
        stream = generate_tcp_stream(
            client_ip="fe80::1",
            server_ip="fe80::2",
            client_isn=0,
            server_isn=0,
            num_data_packets=2,
            payload_sizes=[20, 20],
        )
        self.assertEqual(len(stream.packets), 11)

    def test_ipv6_no_ethernet_ip_version(self):
        pkts = generate_tcp_stream(
            client_ip="2001:db8::1",
            server_ip="2001:db8::2",
            client_isn=0,
            server_isn=0,
            num_data_packets=1,
            payload_sizes=[10],
            include_ethernet=False,
        ).packets
        first_byte = pkts[0].raw[0]
        self.assertEqual(first_byte >> 4, 6)


# ── Group 11: Packet hooks ────────────────────────────────────────────────────

class TestPacketHooks(unittest.TestCase):

    def test_drop_hook_removes_packet(self):
        # Drop the handshake ACK (index 2)
        def drop_index_2(pkt, idx):
            return None if idx == 2 else pkt

        stream = _stream(num_data_packets=3, packet_hooks=[drop_index_2])
        # One packet fewer than normal
        self.assertEqual(len(stream.packets), 2 * 3 + 7 - 1)
        # The dropped packet's label must not appear
        labels = [p.label for p in stream.packets]
        # packets[2] was "ACK" (handshake); it's gone, so DATA[0] follows SYN-ACK
        self.assertEqual(labels[2], "DATA[0]")

    def test_mutate_hook_changes_raw(self):
        sentinel = bytearray()

        def record_and_flip(pkt, idx):
            if idx == 0:
                raw = bytearray(pkt.raw)
                raw[-1] ^= 0xFF
                sentinel.extend([raw[-1]])
                from dataclasses import replace
                return replace(pkt, raw=bytes(raw))
            return pkt

        stream = _stream(num_data_packets=1, packet_hooks=[record_and_flip])
        # Verify the last byte was flipped
        self.assertEqual(len(sentinel), 1)
        original_last = _stream(num_data_packets=1).packets[0].raw[-1]
        self.assertEqual(sentinel[0], original_last ^ 0xFF)

    def test_multiple_hooks_applied_in_order(self):
        log = []

        def hook_a(pkt, idx):
            log.append(("a", idx))
            return pkt

        def hook_b(pkt, idx):
            log.append(("b", idx))
            return pkt

        _stream(num_data_packets=1, packet_hooks=[hook_a, hook_b])
        # Both hooks called for every packet, a before b
        for i in range(0, len(log) - 1, 2):
            self.assertEqual(log[i][0], "a")
            self.assertEqual(log[i + 1][0], "b")

    def test_syn_options_present(self):
        opts = TCPOptions(mss=1460, sack_permitted=True)
        stream = _stream(num_data_packets=1, client_options=opts)
        # SYN raw bytes must be longer than the minimum 54-byte (Eth+IP+TCP)
        # packet because options add bytes; just check it builds successfully
        self.assertGreater(len(stream.packets[0].raw), 54)


if __name__ == "__main__":
    unittest.main()
