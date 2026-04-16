"""Tests for packet_generator.tcp_stream — TCP stream generation."""
from __future__ import annotations

import io
import unittest

import dataclasses

from packeteer.generate.tcp_stream import (
    generate_tcp_stream, TCPStream, TCPStreamConfig, TCPStreamPacket, _pkt_usec,
)
from packeteer.generate.tcp import TCP_SYN, TCP_ACK, TCP_PSH, TCP_FIN, TCPOptions
from packeteer.pcap import write_pcap, LINKTYPE_ETHERNET

_WRAP = 2 ** 32

# Fixed ISNs make sequence-number assertions deterministic.
_CLIENT_ISN = 1000
_SERVER_ISN = 5000

_CONFIG_FIELDS: frozenset[str] = frozenset(
    f.name for f in dataclasses.fields(TCPStreamConfig)
)


def _stream(**kwargs: object) -> TCPStream:
    """Generate a stream with fixed ISNs and sensible defaults."""
    defaults: dict[str, object] = {
        "client_ip": "10.0.0.1",
        "server_ip": "10.0.0.2",
        "client_isn": _CLIENT_ISN,
        "server_isn": _SERVER_ISN,
    }
    defaults.update(kwargs)
    config_kw = {k: defaults.pop(k) for k in list(defaults) if k in _CONFIG_FIELDS}
    cfg = TCPStreamConfig(**config_kw) if config_kw else None
    return generate_tcp_stream(**defaults, config=cfg)


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
            config=TCPStreamConfig(payload_sizes=[4]),
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
        for _i, t in enumerate(times):
            # Each packet's time is bounded by n * gap + jitter
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
            config=TCPStreamConfig(payload_sizes=[20, 20]),
        )
        self.assertEqual(len(stream.packets), 11)

    def test_ipv6_no_ethernet_ip_version(self):
        pkts = generate_tcp_stream(
            client_ip="2001:db8::1",
            server_ip="2001:db8::2",
            client_isn=0,
            server_isn=0,
            num_data_packets=1,
            include_ethernet=False,
            config=TCPStreamConfig(payload_sizes=[10]),
        ).packets
        first_byte = pkts[0].raw[0]
        self.assertEqual(first_byte >> 4, 6)


# ── Group 11: Packet hooks ────────────────────────────────────────────────────

class TestPacketHooks(unittest.TestCase):

    def test_drop_hook_removes_packet(self):
        # Drop the handshake ACK (index 2)
        def drop_index_2(pkt: TCPStreamPacket, idx: int) -> TCPStreamPacket | None:
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

        def record_and_flip(pkt: TCPStreamPacket, idx: int) -> TCPStreamPacket:
            if idx == 0:
                raw = bytearray(pkt.raw)
                raw[-1] ^= 0xFF
                sentinel.extend([raw[-1]])
                from dataclasses import replace
                return replace(pkt, raw=bytes(raw))
            return pkt

        _stream(num_data_packets=1, packet_hooks=[record_and_flip])
        # Verify the last byte was flipped
        self.assertEqual(len(sentinel), 1)
        original_last = _stream(num_data_packets=1).packets[0].raw[-1]
        self.assertEqual(sentinel[0], original_last ^ 0xFF)

    def test_multiple_hooks_applied_in_order(self):
        log = []

        def hook_a(pkt: TCPStreamPacket, idx: int) -> TCPStreamPacket:
            log.append(("a", idx))
            return pkt

        def hook_b(pkt: TCPStreamPacket, idx: int) -> TCPStreamPacket:
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


# ── Group 13: Spurious retransmissions ───────────────────────────────────────

class TestRetransmissions(unittest.TestCase):

    def test_zero_probability_no_retransmits(self):
        n = 5
        stream = _stream(num_data_packets=n, retransmission_probability=0.0)
        retrans = [p for p in stream.packets if p.label.startswith("RETRANS")]
        self.assertEqual(retrans, [])
        self.assertEqual(len(stream.packets), 2 * n + 7)

    def test_full_probability_one_retransmit_per_data_packet(self):
        n = 5
        stream = _stream(num_data_packets=n, retransmission_probability=1.0)
        retrans = [p for p in stream.packets if p.label.startswith("RETRANS")]
        self.assertEqual(len(retrans), n)

    def test_retransmit_labels_match_data_labels(self):
        n = 4
        stream = _stream(num_data_packets=n, retransmission_probability=1.0)
        retrans_indices = {p.label for p in stream.packets if p.label.startswith("RETRANS")}
        expected = {f"RETRANS[{i}]" for i in range(n)}
        self.assertEqual(retrans_indices, expected)

    def test_retransmit_has_same_seq_as_original(self):
        stream = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            retransmission_probability=1.0,
        )
        for i in range(3):
            orig  = next(p for p in stream.packets if p.label == f"DATA[{i}]")
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            self.assertEqual(retrans.seq, orig.seq)

    def test_retransmit_has_same_payload_len_as_original(self):
        stream = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            retransmission_probability=1.0,
        )
        for i in range(3):
            orig    = next(p for p in stream.packets if p.label == f"DATA[{i}]")
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            self.assertEqual(retrans.payload_len, orig.payload_len)

    def test_retransmit_timestamp_after_original(self):
        rto = 0.1
        stream = _stream(
            num_data_packets=3,
            retransmission_probability=1.0,
            retransmission_timeout=rto,
            base_time=0.0,
        )
        for i in range(3):
            orig    = next(p for p in stream.packets if p.label == f"DATA[{i}]")
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            orig_usec   = orig.ts_sec   * 1_000_000 + orig.ts_usec
            retrans_usec = retrans.ts_sec * 1_000_000 + retrans.ts_usec
            self.assertGreaterEqual(retrans_usec, orig_usec + int(rto * 1_000_000))

    def test_retransmit_timestamp_at_least_rto_after_original(self):
        rto = 0.5
        stream = _stream(
            num_data_packets=5,
            retransmission_probability=1.0,
            retransmission_timeout=rto,
            gap_jitter=0.0,
            base_time=0.0,
        )
        rto_usec = int(rto * 1_000_000)
        for pkt in stream.packets:
            if not pkt.label.startswith("RETRANS"):
                continue
            i = int(pkt.label[8:-1])
            orig = next(p for p in stream.packets if p.label == f"DATA[{i}]")
            orig_usec   = orig.ts_sec * 1_000_000 + orig.ts_usec
            retrans_usec = pkt.ts_sec  * 1_000_000 + pkt.ts_usec
            self.assertEqual(retrans_usec, orig_usec + rto_usec)

    def test_output_sorted_by_timestamp_with_retransmissions(self):
        stream = _stream(
            num_data_packets=10,
            retransmission_probability=1.0,
            retransmission_timeout=0.001,
            base_time=0.0,
        )
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in stream.packets]
        self.assertEqual(times, sorted(times))

    def test_subsequent_data_seq_unaffected_by_retransmission(self):
        # Retransmissions must not shift the sequence numbers of later segments.
        stream_without = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            retransmission_probability=0.0,
        )
        stream_with = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            retransmission_probability=1.0,
        )
        for i in range(3):
            seq_without = next(p for p in stream_without.packets if p.label == f"DATA[{i}]").seq
            seq_with    = next(p for p in stream_with.packets    if p.label == f"DATA[{i}]").seq
            self.assertEqual(seq_with, seq_without)

    def test_handshake_and_teardown_not_retransmitted(self):
        stream = _stream(num_data_packets=3, retransmission_probability=1.0)
        non_data_labels = {"SYN", "SYN-ACK", "ACK", "FIN-ACK"}
        retrans_labels = {p.label for p in stream.packets if p.label.startswith("RETRANS")}
        for label in non_data_labels:
            self.assertNotIn(label, retrans_labels)


# ── Group 14: Server RST ──────────────────────────────────────────────────────

class TestServerRst(unittest.TestCase):

    def _rst_stream(self, n: int = 10, **kwargs: object) -> TCPStream:
        return _stream(num_data_packets=n, server_rst_probability=1.0, **kwargs)

    def test_zero_probability_no_rst(self):
        stream = _stream(num_data_packets=5, server_rst_probability=0.0)
        self.assertFalse(any(p.label == "RST" for p in stream.packets))

    def test_rst_present_when_probability_one(self):
        stream = self._rst_stream()
        self.assertTrue(any(p.label == "RST" for p in stream.packets))

    def test_rst_exactly_one_packet(self):
        stream = self._rst_stream()
        self.assertEqual(sum(1 for p in stream.packets if p.label == "RST"), 1)

    def test_no_teardown_after_rst(self):
        stream = self._rst_stream()
        labels = [p.label for p in stream.packets]
        self.assertNotIn("FIN-ACK", labels)

    def test_rst_direction_is_server_to_client(self):
        stream = self._rst_stream()
        rst = next(p for p in stream.packets if p.label == "RST")
        self.assertEqual(rst.direction, "s2c")

    def test_rst_flags(self):
        from packeteer.generate.tcp import TCP_RST, TCP_ACK
        stream = self._rst_stream()
        rst = next(p for p in stream.packets if p.label == "RST")
        self.assertEqual(rst.flags, TCP_RST | TCP_ACK)

    def test_no_acks_after_split_point(self):
        stream = self._rst_stream(n=8)
        # Find highest ACK[i] index present
        ack_indices = [int(p.label[4:-1]) for p in stream.packets
                       if p.label.startswith("ACK[")]
        if not ack_indices:
            return  # split at 0, no normal ACKs — still valid
        max_ack = max(ack_indices)
        # All data packets with index > max_ack must have no corresponding ACK
        data_indices = [int(p.label[5:-1]) for p in stream.packets
                        if p.label.startswith("DATA[")]
        for i in data_indices:
            if i > max_ack:
                self.assertNotIn(f"ACK[{i}]",
                                 [p.label for p in stream.packets])

    def test_some_data_packets_unacked(self):
        # With n=8 and RST certain, at least one DATA must lack an ACK
        stream = self._rst_stream(n=8)
        data_indices = {int(p.label[5:-1]) for p in stream.packets
                        if p.label.startswith("DATA[")}
        ack_indices  = {int(p.label[4:-1]) for p in stream.packets
                        if p.label.startswith("ACK[")}
        self.assertTrue(data_indices - ack_indices)

    def test_rst_timestamp_after_last_normal_ack(self):
        stream = self._rst_stream(n=6, base_time=0.0)
        rst = next(p for p in stream.packets if p.label == "RST")
        ack_pkts = [p for p in stream.packets if p.label.startswith("ACK[")]
        if ack_pkts:
            last_ack_usec = max(p.ts_sec * 1_000_000 + p.ts_usec for p in ack_pkts)
            rst_usec = rst.ts_sec * 1_000_000 + rst.ts_usec
            self.assertGreater(rst_usec, last_ack_usec)

    def test_no_client_data_after_rst_received(self):
        # With zero propagation delay the client learns about the RST immediately;
        # no DATA packet should have a timestamp after the RST.
        stream = _stream(
            num_data_packets=8,
            server_rst_probability=1.0,
            rst_propagation_delay=0.0,
            base_time=0.0,
            gap_jitter=0.0,
        )
        rst = next(p for p in stream.packets if p.label == "RST")
        rst_usec = rst.ts_sec * 1_000_000 + rst.ts_usec
        for p in stream.packets:
            if p.label.startswith("DATA["):
                self.assertLessEqual(p.ts_sec * 1_000_000 + p.ts_usec, rst_usec)

    def test_propagation_delay_allows_extra_data(self):
        # With a propagation delay larger than the inter-packet gap the client
        # sends at least one extra DATA packet before learning about the RST.
        gap = 0.001
        delay = 0.005  # 5 × gap → client sends ~5 extra packets
        stream = _stream(
            num_data_packets=20,
            server_rst_probability=1.0,
            rst_propagation_delay=delay,
            inter_packet_gap=gap,
            base_time=0.0,
            gap_jitter=0.0,
        )
        rst = next(p for p in stream.packets if p.label == "RST")
        rst_usec = rst.ts_sec * 1_000_000 + rst.ts_usec
        ack_indices = {int(p.label[4:-1]) for p in stream.packets
                       if p.label.startswith("ACK[")}
        # DATA packets after the split but before client learns RST
        extra = [p for p in stream.packets
                 if p.label.startswith("DATA[")
                 and int(p.label[5:-1]) not in ack_indices
                 and (p.ts_sec * 1_000_000 + p.ts_usec) <= rst_usec +
                     int(delay * 1_000_000)]
        self.assertGreater(len(extra), 0)

    def test_no_server_packets_after_rst(self):
        # After the RST the server must not send any further packets.
        stream = _stream(
            num_data_packets=8,
            server_rst_probability=1.0,
            base_time=0.0,
            gap_jitter=0.0,
        )
        rst = next(p for p in stream.packets if p.label == "RST")
        rst_usec = rst.ts_sec * 1_000_000 + rst.ts_usec
        for p in stream.packets:
            if p.direction == "s2c" and p.label != "RST":
                self.assertLessEqual(p.ts_sec * 1_000_000 + p.ts_usec, rst_usec)

    def test_output_sorted_after_rst(self):
        stream = self._rst_stream(n=8, base_time=0.0)
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in stream.packets]
        self.assertEqual(times, sorted(times))

    def test_handshake_intact_after_rst(self):
        stream = self._rst_stream()
        labels = [p.label for p in stream.packets]
        self.assertIn("SYN", labels)
        self.assertIn("SYN-ACK", labels)
        self.assertIn("ACK", labels)


# ── Group 15: Payload corruption ─────────────────────────────────────────────

class TestPayloadCorruption(unittest.TestCase):

    def test_zero_probability_no_corruption(self):
        stream = _stream(num_data_packets=5, payload_corruption_probability=0.0)
        labels = [p.label for p in stream.packets]
        self.assertFalse(any(lbl.startswith("CORRUPT") for lbl in labels))

    def test_full_probability_one_corrupt_per_data_packet(self):
        n = 4
        stream = _stream(num_data_packets=n, payload_corruption_probability=1.0)
        corrupt = [p for p in stream.packets if p.label.startswith("CORRUPT")]
        self.assertEqual(len(corrupt), n)

    def test_corrupt_labels_match_data_indices(self):
        n = 3
        stream = _stream(num_data_packets=n, payload_corruption_probability=1.0)
        corrupt_indices = {p.label for p in stream.packets if p.label.startswith("CORRUPT")}
        self.assertEqual(corrupt_indices, {f"CORRUPT[{i}]" for i in range(n)})

    def test_corrupt_packet_has_same_seq_as_original(self):
        stream = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            payload_corruption_probability=1.0,
            retransmission_probability=0.0,
        )
        for i in range(3):
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            corrupt = next(p for p in stream.packets if p.label == f"CORRUPT[{i}]")
            self.assertEqual(corrupt.seq, retrans.seq)

    def test_corrupt_raw_differs_from_retransmit_raw(self):
        stream = _stream(
            num_data_packets=2,
            payload_sizes=[100, 100],
            payload_corruption_probability=1.0,
        )
        for i in range(2):
            corrupt = next(p for p in stream.packets if p.label == f"CORRUPT[{i}]")
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            self.assertNotEqual(corrupt.raw, retrans.raw)

    def test_corrupt_differs_by_exactly_one_byte(self):
        stream = _stream(
            num_data_packets=1,
            payload_sizes=[50],
            payload_corruption_probability=1.0,
            gap_jitter=0.0,
        )
        corrupt = next(p for p in stream.packets if p.label == "CORRUPT[0]")
        retrans = next(p for p in stream.packets if p.label == "RETRANS[0]")
        diffs = sum(a != b for a, b in zip(corrupt.raw, retrans.raw, strict=False))
        self.assertEqual(diffs, 1)

    def test_retransmit_timestamp_after_corrupt(self):
        rto = 0.1
        stream = _stream(
            num_data_packets=3,
            payload_corruption_probability=1.0,
            retransmission_timeout=rto,
            base_time=0.0,
        )
        rto_usec = int(rto * 1_000_000)
        for i in range(3):
            corrupt = next(p for p in stream.packets if p.label == f"CORRUPT[{i}]")
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            corrupt_usec = corrupt.ts_sec * 1_000_000 + corrupt.ts_usec
            retrans_usec = retrans.ts_sec * 1_000_000 + retrans.ts_usec
            self.assertGreaterEqual(retrans_usec, corrupt_usec + rto_usec)

    def test_ack_timestamp_after_retransmit(self):
        stream = _stream(
            num_data_packets=3,
            payload_corruption_probability=1.0,
            retransmission_timeout=0.1,
            base_time=0.0,
            gap_jitter=0.0,
        )
        for i in range(3):
            retrans = next(p for p in stream.packets if p.label == f"RETRANS[{i}]")
            ack = next(p for p in stream.packets if p.label == f"ACK[{i}]")
            retrans_usec = retrans.ts_sec * 1_000_000 + retrans.ts_usec
            ack_usec = ack.ts_sec * 1_000_000 + ack.ts_usec
            self.assertGreater(ack_usec, retrans_usec)

    def test_output_sorted_by_timestamp_with_corruption(self):
        stream = _stream(
            num_data_packets=10,
            payload_corruption_probability=1.0,
            retransmission_timeout=0.001,
            base_time=0.0,
        )
        times = [p.ts_sec * 1_000_000 + p.ts_usec for p in stream.packets]
        self.assertEqual(times, sorted(times))

    def test_subsequent_data_seq_unaffected_by_corruption(self):
        stream_clean = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            payload_corruption_probability=0.0,
        )
        stream_corrupt = _stream(
            num_data_packets=3,
            payload_sizes=[100, 200, 300],
            payload_corruption_probability=1.0,
        )
        for i in range(3):
            seq_clean   = next(p for p in stream_clean.packets   if p.label == f"DATA[{i}]").seq
            seq_corrupt = next(p for p in stream_corrupt.packets if p.label == f"RETRANS[{i}]").seq
            self.assertEqual(seq_corrupt, seq_clean)


# ── Group 16: Middlebox fragmentation ────────────────────────────────────────

class TestMiddleboxFragmentation(unittest.TestCase):
    """Group 16: mtu causes large packets to be IP-fragmented."""

    # Use a small MTU that will fragment typical data packets.
    # Each data packet has at least 40 bytes payload + 20 IP + 20 TCP = 80 bytes.
    # With MTU=100, every data packet (≥80 bytes IP layer) will be split
    # if the payload pushes it over 100.  With min_payload=200, all are split.
    _MTU = 576  # conservative router MTU

    def _make_stream(self, **kw: object) -> TCPStream:
        defaults: dict[str, object] = {
            "client_ip": "10.0.0.1",
            "server_ip": "10.0.0.2",
            "num_data_packets": 5,
            "min_payload": 600,   # guarantees all data packets exceed any sub-640 MTU
            "max_payload": 600,
            "payload_distribution": "fixed",
            "client_isn": 1000,
            "server_isn": 2000,
            "base_time": 1_000_000.0,
            "inter_packet_gap": 0.001,
        }
        defaults.update(kw)
        config_kw = {k: defaults.pop(k) for k in list(defaults) if k in _CONFIG_FIELDS}
        cfg = TCPStreamConfig(**config_kw) if config_kw else None
        return generate_tcp_stream(**defaults, config=cfg)

    def test_no_fragmentation_when_mtu_none(self):
        """No FRAG packets appear when mtu is None (default)."""
        stream = self._make_stream()
        frag_pkts = [p for p in stream.packets if p.label.startswith("FRAG[")]
        self.assertEqual(frag_pkts, [])

    def test_no_fragmentation_when_packets_fit(self):
        """No fragmentation when all packets fit within the MTU."""
        # SYN/ACK/FIN are tiny; data payloads are 40 bytes → IP = 80 bytes
        stream = self._make_stream(min_payload=40, max_payload=40, mtu=1500)
        frag_pkts = [p for p in stream.packets if p.label.startswith("FRAG[")]
        self.assertEqual(frag_pkts, [])

    def test_data_packets_are_fragmented(self):
        """Large data packets are replaced by FRAG[DATA[i]][n] entries."""
        stream = self._make_stream(mtu=self._MTU)
        frag_pkts = [p for p in stream.packets if p.label.startswith("FRAG[DATA[")]
        self.assertGreater(len(frag_pkts), 0)

    def test_original_data_labels_absent(self):
        """After fragmentation, no original DATA[i] label remains."""
        stream = self._make_stream(mtu=self._MTU)
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(data_pkts, [])

    def test_frag_indices_start_at_zero(self):
        """The first fragment of each DATA packet is labelled FRAG[DATA[i]][0]."""
        stream = self._make_stream(mtu=self._MTU)
        for i in range(5):
            frag0 = next(
                (p for p in stream.packets if p.label == f"FRAG[DATA[{i}]][0]"),
                None,
            )
            self.assertIsNotNone(frag0, f"FRAG[DATA[{i}]][0] not found")

    def test_each_fragment_fits_in_mtu(self):
        """Every fragment's IP-layer size is ≤ mtu."""
        mtu = self._MTU
        stream = self._make_stream(mtu=mtu)
        eth_offset = 14  # Ethernet header
        for pkt in stream.packets:
            ip_size = len(pkt.raw) - eth_offset
            self.assertLessEqual(
                ip_size, mtu,
                f"Packet {pkt.label!r} IP-size {ip_size} exceeds MTU {mtu}",
            )

    def test_timestamps_unique(self):
        """All fragment packets have unique timestamps."""
        stream = self._make_stream(mtu=self._MTU)
        ts_list = [(p.ts_sec, p.ts_usec) for p in stream.packets]
        self.assertEqual(len(ts_list), len(set(ts_list)))

    def test_timestamps_sorted(self):
        """Output is sorted by timestamp after fragmentation."""
        stream = self._make_stream(mtu=self._MTU)
        ts_list = [(p.ts_sec, p.ts_usec) for p in stream.packets]
        self.assertEqual(ts_list, sorted(ts_list))

    def test_frag0_direction_preserved(self):
        """Fragment 0 inherits direction from the original packet."""
        stream = self._make_stream(mtu=self._MTU)
        for pkt in stream.packets:
            if pkt.label.startswith("FRAG[DATA[") and pkt.label.endswith("][0]"):
                self.assertEqual(pkt.direction, "c2s")

    def test_frag0_seq_ack_preserved(self):
        """Fragment 0 inherits seq/ack from the original DATA packet.

        Flags are not checked because PSH is set probabilistically and two
        separate stream generations may produce different values.
        """
        # Generate without fragmentation to get reference seq/ack values;
        # fix ISNs so both streams agree on sequence numbers.
        ref = self._make_stream(client_isn=500, server_isn=900)
        stream = self._make_stream(mtu=self._MTU,
                                   client_isn=500, server_isn=900)
        for i in range(5):
            ref_data = next(p for p in ref.packets if p.label == f"DATA[{i}]")
            frag0 = next(p for p in stream.packets
                         if p.label == f"FRAG[DATA[{i}]][0]")
            self.assertEqual(frag0.seq, ref_data.seq)
            self.assertEqual(frag0.ack, ref_data.ack)

    def test_subsequent_frags_have_zero_seq(self):
        """Fragments after index 0 have seq=0, ack=0, flags=0."""
        stream = self._make_stream(mtu=self._MTU)
        for pkt in stream.packets:
            if not pkt.label.startswith("FRAG[DATA["):
                continue
            # Extract fragment index from "FRAG[DATA[i]][n]"
            frag_idx = int(pkt.label.rsplit("[", 1)[1].rstrip("]"))
            if frag_idx > 0:
                self.assertEqual(pkt.seq, 0)
                self.assertEqual(pkt.ack, 0)
                self.assertEqual(pkt.flags, 0)

    def test_small_packets_not_fragmented(self):
        """Handshake and teardown packets (SYN, ACK, FIN-ACK) are not fragmented."""
        stream = self._make_stream(mtu=self._MTU)
        for label in ("SYN", "SYN-ACK", "FIN-ACK", "ACK"):
            frag = next(
                (p for p in stream.packets
                 if p.label.startswith(f"FRAG[{label}")),
                None,
            )
            self.assertIsNone(frag,
                              f"Unexpected fragmentation of {label}: {frag}")

    def test_server_acks_not_fragmented(self):
        """Server ACK[i] packets (pure ACKs, no payload) are not fragmented."""
        stream = self._make_stream(mtu=self._MTU)
        frag_acks = [p for p in stream.packets
                     if p.label.startswith("FRAG[ACK[")]
        self.assertEqual(frag_acks, [])

    def test_ipv6_fragmentation(self):
        """IPv6 data packets are fragmented using Fragment Extension Headers."""
        stream = generate_tcp_stream(
            client_ip="2001:db8::1",
            server_ip="2001:db8::2",
            num_data_packets=3,
            min_payload=600,
            max_payload=600,
            payload_distribution="fixed",
            client_isn=1000,
            server_isn=2000,
            mtu=self._MTU,
            config=TCPStreamConfig(base_time=1_000_000.0),
        )
        frag_pkts = [p for p in stream.packets if p.label.startswith("FRAG[DATA[")]
        self.assertGreater(len(frag_pkts), 0)
        eth_offset = 14
        for pkt in frag_pkts:
            # Check next_header in IPv6 base header = 44 (Fragment ext)
            next_header = pkt.raw[eth_offset + 6]
            self.assertEqual(next_header, 44,
                             f"{pkt.label}: expected IPv6 next_header=44, got {next_header}")
            ip_size = len(pkt.raw) - eth_offset
            self.assertLessEqual(ip_size, self._MTU)

    def test_no_ethernet_ipv4_fragmentation(self):
        """Fragmentation works correctly when include_ethernet=False."""
        stream = generate_tcp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            num_data_packets=3,
            min_payload=600,
            max_payload=600,
            payload_distribution="fixed",
            client_isn=1000,
            server_isn=2000,
            include_ethernet=False,
            mtu=self._MTU,
            config=TCPStreamConfig(base_time=1_000_000.0),
        )
        frag_pkts = [p for p in stream.packets if p.label.startswith("FRAG[DATA[")]
        self.assertGreater(len(frag_pkts), 0)
        for pkt in frag_pkts:
            self.assertLessEqual(len(pkt.raw), self._MTU)

    def test_fragment_count_correct(self):
        """Number of fragments per data packet is ceil(transport_data / max_frag_data)."""
        # IPv4 with Ethernet: IP header=20, transport_data = 20 (TCP) + 600 (payload) = 620 bytes
        # MTU=576: max_data = (576-20) & ~7 = 552 bytes
        # fragments = ceil(620 / 552) = 2
        stream = self._make_stream(mtu=576)
        frag0_count = sum(
            1 for p in stream.packets if p.label.endswith("][0]")
            and p.label.startswith("FRAG[DATA[")
        )
        frag1_count = sum(
            1 for p in stream.packets if p.label.endswith("][1]")
            and p.label.startswith("FRAG[DATA[")
        )
        # All 5 data packets → 5 frag-0 and 5 frag-1
        self.assertEqual(frag0_count, 5)
        self.assertEqual(frag1_count, 5)


# ── Group 17: Stray packet injection ─────────────────────────────────────────

class TestStrayPackets(unittest.TestCase):
    """Group 17: stray_packet_count injects forged TCP hijack packets."""

    def _make_stream(self, **kw: object) -> TCPStream:
        defaults: dict[str, object] = {
            "client_ip": "10.0.0.1",
            "server_ip": "10.0.0.2",
            "num_data_packets": 10,
            "min_payload": 40,
            "max_payload": 200,
            "client_isn": 1000,
            "server_isn": 2000,
            "base_time": 1_000_000.0,
            "inter_packet_gap": 0.001,
        }
        defaults.update(kw)
        config_kw = {k: defaults.pop(k) for k in list(defaults) if k in _CONFIG_FIELDS}
        cfg = TCPStreamConfig(**config_kw) if config_kw else None
        return generate_tcp_stream(**defaults, config=cfg)

    def test_no_strays_by_default(self):
        """No STRAY packets when stray_packet_count=0 (default)."""
        stream = self._make_stream()
        self.assertEqual([p for p in stream.packets if p.label.startswith("STRAY[")], [])

    def test_correct_count(self):
        """Exactly stray_packet_count STRAY packets are produced."""
        for n in (1, 3, 10):
            with self.subTest(n=n):
                stream = self._make_stream(stray_packet_count=n)
                strays = [p for p in stream.packets if p.label.startswith("STRAY[")]
                self.assertEqual(len(strays), n)

    def test_labels_sequential(self):
        """Stray packets are labelled STRAY[0], STRAY[1], etc."""
        n = 5
        stream = self._make_stream(stray_packet_count=n)
        labels = {p.label for p in stream.packets if p.label.startswith("STRAY[")}
        self.assertEqual(labels, {f"STRAY[{i}]" for i in range(n)})

    def test_direction_c2s(self):
        """All stray packets are client→server."""
        stream = self._make_stream(stray_packet_count=5)
        for p in stream.packets:
            if p.label.startswith("STRAY["):
                self.assertEqual(p.direction, "c2s")

    def test_flags_psh_ack(self):
        """Stray packets carry PSH|ACK flags."""
        from packeteer.generate.tcp import TCP_ACK
        stream = self._make_stream(stray_packet_count=5)
        for p in stream.packets:
            if p.label.startswith("STRAY["):
                self.assertEqual(p.flags, TCP_ACK | TCP_PSH)

    def test_payload_all_x(self):
        """Stray packet payloads consist entirely of b'x' bytes."""
        stream = self._make_stream(stray_packet_count=5)
        eth_ip_tcp = 14 + 20 + 20  # Ethernet + IPv4 + TCP (no options)
        for p in stream.packets:
            if not p.label.startswith("STRAY["):
                continue
            # Payload starts after Ethernet+IP+TCP headers
            payload = p.raw[eth_ip_tcp:]
            self.assertTrue(payload, "stray packet has no payload")
            self.assertEqual(payload, b'x' * len(payload))

    def test_payload_size_within_range(self):
        """Stray payload sizes are within [min_payload, max_payload]."""
        stream = self._make_stream(stray_packet_count=10, min_payload=50, max_payload=150)
        eth_ip_tcp = 14 + 20 + 20
        for p in stream.packets:
            if p.label.startswith("STRAY["):
                payload_len = len(p.raw) - eth_ip_tcp
                self.assertGreaterEqual(payload_len, 50)
                self.assertLessEqual(payload_len, 150)

    def test_seq_stolen_from_data(self):
        """Each stray packet's seq matches a real DATA packet's seq."""
        stream = self._make_stream(stray_packet_count=10)
        data_seqs = {p.seq for p in stream.packets if p.label.startswith("DATA[")}
        for p in stream.packets:
            if p.label.startswith("STRAY["):
                self.assertIn(p.seq, data_seqs,
                              f"{p.label} seq={p.seq} not found in data seqs")

    def test_same_endpoints(self):
        """Stray packets use the same IP/port as the real client."""
        import struct
        stream = self._make_stream(stray_packet_count=5)
        # Get src IP from a real DATA packet for comparison
        ref_data = next(p for p in stream.packets if p.label.startswith("DATA["))
        ref_src_ip = ref_data.raw[26:30]   # IPv4 src at bytes 26-29
        ref_src_port = struct.unpack("!H", ref_data.raw[34:36])[0]
        for p in stream.packets:
            if not p.label.startswith("STRAY["):
                continue
            self.assertEqual(p.raw[26:30], ref_src_ip)
            self.assertEqual(struct.unpack("!H", p.raw[34:36])[0], ref_src_port)

    def test_timestamps_unique(self):
        """All packet timestamps are unique after stray injection."""
        stream = self._make_stream(stray_packet_count=10)
        ts_list = [_pkt_usec(p) for p in stream.packets]
        self.assertEqual(len(ts_list), len(set(ts_list)))

    def test_timestamps_sorted(self):
        """Output is sorted by timestamp after stray injection."""
        stream = self._make_stream(stray_packet_count=10)
        ts_list = [(p.ts_sec, p.ts_usec) for p in stream.packets]
        self.assertEqual(ts_list, sorted(ts_list))

    def test_timestamps_within_data_window(self):
        """Stray timestamps fall within the data-transfer time window."""
        stream = self._make_stream(stray_packet_count=20)
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        ts_lo = min(_pkt_usec(p) for p in data_pkts)
        ts_hi = max(_pkt_usec(p) for p in data_pkts)
        for p in stream.packets:
            if p.label.startswith("STRAY["):
                ts = _pkt_usec(p)
                self.assertGreaterEqual(ts, ts_lo)
                self.assertLessEqual(ts, ts_hi)

    def test_stream_seq_ack_unaffected(self):
        """Stray injection does not alter the real stream's seq/ack numbers."""
        kw: dict[str, object] = {
            "client_isn": 500, "server_isn": 900,
            "min_payload": 100, "max_payload": 100,
            "payload_distribution": "fixed",
        }
        ref = self._make_stream(**kw)
        stream = self._make_stream(stray_packet_count=10, **kw)
        ref_data = [(p.seq, p.ack) for p in ref.packets if p.label.startswith("DATA[")]
        got_data = [(p.seq, p.ack) for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(ref_data, got_data)

    def test_timing_window_constrains_timestamps(self):
        """With stray_timing_window=N each stray falls within N packets of its ref."""
        window = 2
        stream = self._make_stream(
            stray_packet_count=10,
            stray_timing_window=window,
            inter_packet_gap=0.01,   # wider gap so the window is meaningful
        )
        # Replicate the pre-injection sorted view the implementation uses:
        # exclude stray packets, which were not present when bounds were computed.
        non_strays = sorted(
            [p for p in stream.packets if not p.label.startswith("STRAY[")],
            key=lambda p: (p.ts_sec, p.ts_usec),
        )
        ts_map = {id(p): i for i, p in enumerate(non_strays)}

        # For each stray, find a data packet with matching seq and check bounds
        data_by_seq = {p.seq: p for p in stream.packets if p.label.startswith("DATA[")}
        for stray in stream.packets:
            if not stray.label.startswith("STRAY["):
                continue
            ref = data_by_seq.get(stray.seq)
            if ref is None:
                continue  # ref may have been filtered by RST; skip
            ref_idx = ts_map[id(ref)]
            lo_idx = max(0, ref_idx - window)
            hi_idx = min(len(non_strays) - 1, ref_idx + window)
            ts_lo = _pkt_usec(non_strays[lo_idx])
            ts_hi = _pkt_usec(non_strays[hi_idx])
            stray_ts = _pkt_usec(stray)
            self.assertGreaterEqual(stray_ts, ts_lo,
                                    f"{stray.label} ts {stray_ts} < window lo {ts_lo}")
            self.assertLessEqual(stray_ts, ts_hi,
                                 f"{stray.label} ts {stray_ts} > window hi {ts_hi}")

    def test_timing_window_none_uses_full_window(self):
        """Without stray_timing_window strays can appear anywhere in the data window."""
        # Use a large stream so the full window is much wider than any local window
        stream = self._make_stream(
            num_data_packets=50,
            stray_packet_count=20,
            stray_timing_window=None,
            inter_packet_gap=0.01,
        )
        strays = [p for p in stream.packets if p.label.startswith("STRAY[")]
        self.assertEqual(len(strays), 20)

    def test_zero_data_packets_no_crash(self):
        """stray_packet_count > 0 with num_data_packets=0 produces no stray packets."""
        stream = generate_tcp_stream(
            client_ip="10.0.0.1",
            server_ip="10.0.0.2",
            num_data_packets=0,
            config=TCPStreamConfig(stray_packet_count=5, base_time=1_000_000.0),
        )
        strays = [p for p in stream.packets if p.label.startswith("STRAY[")]
        self.assertEqual(strays, [])


if __name__ == "__main__":
    unittest.main()
