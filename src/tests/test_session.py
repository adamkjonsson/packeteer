"""Tests for packeteer.generate.session — session builder API."""
from __future__ import annotations

import unittest

from packeteer.generate.session import (
    TCPSession, UDPSession, SCTPSession,
    tcp_handshake, tcp_teardown, sctp_handshake,
)
from packeteer.generate.tcp_stream import TCPStream, TCPStreamPacket
from packeteer.generate.udp_stream import UDPStream, UDPStreamPacket
from packeteer.generate.sctp_stream import SCTPStream
from packeteer.generate.tcp import TCP_PSH

_C_IP = "10.0.0.1"
_S_IP = "10.0.0.2"


# ── TCPSession ────────────────────────────────────────────────────────────────

class TestTCPSession(unittest.TestCase):

    def _session(self, **kwargs: object) -> TCPSession:
        defaults: dict[str, object] = {
            "client_ip": _C_IP, "server_ip": _S_IP, "server_port": 80,
            "client_isn": 1000, "server_isn": 5000,
        }
        defaults.update(kwargs)
        return TCPSession(**defaults)  # type: ignore[arg-type]

    def test_build_returns_tcp_stream(self) -> None:
        stream = self._session().send(b"hello").build()
        self.assertIsInstance(stream, TCPStream)

    def test_empty_session_has_seven_packets(self) -> None:
        # SYN, SYN-ACK, ACK (handshake) + FIN-ACK, ACK, FIN-ACK, ACK (teardown)
        stream = self._session().build()
        self.assertEqual(len(stream.packets), 7)

    def test_handshake_labels(self) -> None:
        stream = self._session().build()
        labels = [p.label for p in stream.packets]
        self.assertEqual(labels[:3], ["SYN", "SYN-ACK", "ACK"])

    def test_teardown_labels(self) -> None:
        stream = self._session().build()
        labels = [p.label for p in stream.packets]
        self.assertEqual(labels[-4:], ["FIN-ACK", "ACK", "FIN-ACK", "ACK"])

    def test_send_produces_data_and_ack_packets(self) -> None:
        stream = self._session().send(b"x" * 10).build()
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        ack_pkts  = [p for p in stream.packets if p.label.startswith("ACK[")]
        self.assertEqual(len(data_pkts), 1)
        self.assertEqual(len(ack_pkts), 1)

    def test_recv_produces_server_data(self) -> None:
        stream = self._session().recv(b"response").build()
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(len(data_pkts), 1)
        self.assertEqual(data_pkts[0].direction, "s2c")

    def test_large_payload_segmented(self) -> None:
        payload = b"a" * 4000
        stream = self._session(mss=1460).send(payload).build()
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        # ceil(4000 / 1460) = 3 segments
        self.assertEqual(len(data_pkts), 3)

    def test_psh_on_last_segment_only(self) -> None:
        payload = b"b" * 3000
        stream = self._session(mss=1460).send(payload).build()
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        for pkt in data_pkts[:-1]:
            self.assertFalse(pkt.flags & TCP_PSH, "only the last segment should have PSH")
        self.assertTrue(data_pkts[-1].flags & TCP_PSH)

    def test_send_many(self) -> None:
        stream = (self._session()
                  .send_many(3, lambda i: f"msg{i}".encode())
                  .build())
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(len(data_pkts), 3)
        for pkt in data_pkts:
            self.assertEqual(pkt.direction, "c2s")

    def test_recv_many(self) -> None:
        stream = (self._session()
                  .recv_many(2, lambda i: b"resp")
                  .build())
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(len(data_pkts), 2)
        for pkt in data_pkts:
            self.assertEqual(pkt.direction, "s2c")

    def test_chaining_returns_self(self) -> None:
        sess = self._session()
        self.assertIs(sess.send(b"a"), sess)
        self.assertIs(sess.recv(b"b"), sess)
        self.assertIs(sess.send_many(1, lambda _: b"x"), sess)
        self.assertIs(sess.recv_many(1, lambda _: b"y"), sess)

    def test_packets_are_tcp_stream_packets(self) -> None:
        stream = self._session().send(b"data").build()
        for pkt in stream.packets:
            self.assertIsInstance(pkt, TCPStreamPacket)

    def test_timestamps_monotonically_increase(self) -> None:
        stream = self._session().send(b"x").recv(b"y").build()
        ts = [(p.ts_sec, p.ts_usec) for p in stream.packets]
        self.assertEqual(ts, sorted(ts))

    def test_no_ethernet_header(self) -> None:
        stream = self._session(include_ethernet=False).send(b"hi").build()
        # raw starts with IP version nibble 4 or 6, not 0x45 Ethernet prefix
        first_byte = stream.packets[0].raw[0]
        self.assertIn(first_byte >> 4, (4, 6))

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import TCPSession  # noqa: F401


# ── UDPSession ────────────────────────────────────────────────────────────────

class TestUDPSession(unittest.TestCase):

    def _session(self, **kwargs: object) -> UDPSession:
        defaults: dict[str, object] = {
            "client_ip": _C_IP, "server_ip": _S_IP, "server_port": 53,
        }
        defaults.update(kwargs)
        return UDPSession(**defaults)  # type: ignore[arg-type]

    def test_build_returns_udp_stream(self) -> None:
        stream = self._session().send(b"query").build()
        self.assertIsInstance(stream, UDPStream)

    def test_empty_session_produces_no_packets(self) -> None:
        stream = self._session().build()
        self.assertEqual(len(stream.packets), 0)

    def test_send_produces_c2s_packet(self) -> None:
        stream = self._session().send(b"q").build()
        self.assertEqual(len(stream.packets), 1)
        self.assertEqual(stream.packets[0].direction, "c2s")

    def test_recv_produces_s2c_packet(self) -> None:
        stream = self._session().recv(b"r").build()
        self.assertEqual(stream.packets[0].direction, "s2c")

    def test_query_response(self) -> None:
        stream = self._session().send(b"query").recv(b"response").build()
        self.assertEqual(len(stream.packets), 2)
        self.assertEqual(stream.packets[0].direction, "c2s")
        self.assertEqual(stream.packets[1].direction, "s2c")

    def test_send_many(self) -> None:
        stream = (self._session()
                  .send_many(5, lambda i: f"log {i}".encode())
                  .build())
        self.assertEqual(len(stream.packets), 5)
        for pkt in stream.packets:
            self.assertEqual(pkt.direction, "c2s")

    def test_recv_many(self) -> None:
        stream = (self._session()
                  .recv_many(3, lambda _: b"data")
                  .build())
        self.assertEqual(len(stream.packets), 3)
        for pkt in stream.packets:
            self.assertEqual(pkt.direction, "s2c")

    def test_payload_length_preserved(self) -> None:
        payload = b"x" * 200
        stream = self._session().send(payload).build()
        self.assertEqual(stream.packets[0].payload_len, 200)

    def test_timestamps_monotonically_increase(self) -> None:
        stream = self._session().send_many(4, lambda _: b"x").build()
        ts = [(p.ts_sec, p.ts_usec) for p in stream.packets]
        self.assertEqual(ts, sorted(ts))

    def test_packets_are_udp_stream_packets(self) -> None:
        stream = self._session().send(b"hi").build()
        for pkt in stream.packets:
            self.assertIsInstance(pkt, UDPStreamPacket)

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import UDPSession  # noqa: F401


# ── SCTPSession ───────────────────────────────────────────────────────────────

class TestSCTPSession(unittest.TestCase):

    def _session(self, **kwargs: object) -> SCTPSession:
        defaults: dict[str, object] = {
            "client_ip": _C_IP, "server_ip": _S_IP, "server_port": 36412,
        }
        defaults.update(kwargs)
        return SCTPSession(**defaults)  # type: ignore[arg-type]

    def test_build_returns_sctp_stream(self) -> None:
        stream = self._session().send(b"data").build()
        self.assertIsInstance(stream, SCTPStream)

    def test_empty_session_has_seven_packets(self) -> None:
        # INIT, INIT-ACK, COOKIE-ECHO, COOKIE-ACK + SHUTDOWN, SHUTDOWN-ACK, SHUTDOWN-COMPLETE
        stream = self._session().build()
        self.assertEqual(len(stream.packets), 7)

    def test_handshake_labels(self) -> None:
        stream = self._session().build()
        labels = [p.label for p in stream.packets[:4]]
        self.assertEqual(labels, ["INIT", "INIT-ACK", "COOKIE-ECHO", "COOKIE-ACK"])

    def test_shutdown_labels(self) -> None:
        stream = self._session().build()
        labels = [p.label for p in stream.packets[-3:]]
        self.assertEqual(labels, ["SHUTDOWN", "SHUTDOWN-ACK", "SHUTDOWN-COMPLETE"])

    def test_data_exchange_packet_count(self) -> None:
        stream = self._session().send(b"req").recv(b"resp").build()
        # 4 handshake + 2*2 data+sack + 3 shutdown = 11
        self.assertEqual(len(stream.packets), 11)

    def test_send_many(self) -> None:
        stream = (self._session()
                  .send_many(3, lambda i: f"record{i}".encode())
                  .build())
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(len(data_pkts), 3)
        for pkt in data_pkts:
            self.assertEqual(pkt.direction, "c2s")

    def test_recv_many(self) -> None:
        stream = (self._session()
                  .recv_many(2, lambda _: b"resp")
                  .build())
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        self.assertEqual(len(data_pkts), 2)
        for pkt in data_pkts:
            self.assertEqual(pkt.direction, "s2c")

    def test_tsn_increments(self) -> None:
        stream = (self._session()
                  .send(b"a").send(b"b").send(b"c")
                  .build())
        data_pkts = [p for p in stream.packets if p.label.startswith("DATA[")]
        tsns = [p.tsn for p in data_pkts]
        self.assertEqual(tsns[1] - tsns[0], 1)
        self.assertEqual(tsns[2] - tsns[1], 1)

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import SCTPSession  # noqa: F401


# ── Standalone helpers ────────────────────────────────────────────────────────

class TestTCPHandshake(unittest.TestCase):

    def _hs(self, **kwargs: object) -> list[bytes]:
        defaults: dict[str, object] = {
            "client_ip": _C_IP, "server_ip": _S_IP,
            "client_isn": 1000, "server_isn": 5000,
        }
        defaults.update(kwargs)
        return tcp_handshake(**defaults)  # type: ignore[arg-type]

    def test_returns_three_packets(self) -> None:
        self.assertEqual(len(self._hs()), 3)

    def test_all_bytes(self) -> None:
        for pkt in self._hs():
            self.assertIsInstance(pkt, bytes)
            self.assertGreater(len(pkt), 0)

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import tcp_handshake  # noqa: F401


class TestTCPTeardown(unittest.TestCase):

    def test_returns_four_packets(self) -> None:
        pkts = tcp_teardown(
            client_ip=_C_IP, server_ip=_S_IP,
        )
        self.assertEqual(len(pkts), 4)

    def test_all_bytes(self) -> None:
        for pkt in tcp_teardown(client_ip=_C_IP, server_ip=_S_IP):
            self.assertIsInstance(pkt, bytes)
            self.assertGreater(len(pkt), 0)

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import tcp_teardown  # noqa: F401


class TestSCTPHandshake(unittest.TestCase):

    def test_returns_four_packets(self) -> None:
        pkts = sctp_handshake(client_ip=_C_IP, server_ip=_S_IP)
        self.assertEqual(len(pkts), 4)

    def test_all_bytes(self) -> None:
        for pkt in sctp_handshake(client_ip=_C_IP, server_ip=_S_IP):
            self.assertIsInstance(pkt, bytes)
            self.assertGreater(len(pkt), 0)

    def test_import_from_generate_package(self) -> None:
        from packeteer.generate import sctp_handshake  # noqa: F401


if __name__ == "__main__":
    unittest.main()
