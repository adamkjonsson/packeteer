"""A UDP datagram travels the way its message says (#195).

`generate_udp_stream` sent every datagram from the client, so a DNS stream
replayed from queries and responses put the responses on the wire from the
client's port to the server's.  The direction is now read from each message:
a packet's ``packet_metadata.direction``, or its addresses when a parsed
capture carries none; a ``"direction"`` key beside a wrapped section; and
``c2s`` for a bare one.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from packeteer import protocols
from packeteer.app import protocol_conversation, protocol_messages, protocol_payload_fn
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.base import AppMessage
from packeteer.generate.udp_stream import UDPStreamConfig, generate_udp_stream
from packeteer.parse import parse_packet

_QUERY = {"id": 1, "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}]}
_RESPONSE = {
    "id": 1, "flags": {"qr": True},
    "questions": [{"name": "www.example.com.", "qtype": 1, "qclass": 1}],
    "answers": [{"name": "www.example.com.", "rtype": 1, "rclass": 1, "ttl": 60,
                 "rdata": {"address": "192.0.2.7"}}],
}


def _dns() -> protocols.AppProtocol:
    proto = protocols.for_section("dns")
    assert proto is not None
    return proto


def _packet(section: dict, src: tuple[str, int], dst: tuple[str, int],
            direction: str | None = None) -> dict:
    """Return a packet as `packeteer parse` writes it, with a direction if given."""
    meta: dict = {"packet_num": 1}
    if direction is not None:
        meta["direction"] = direction
    return {
        "network": {"src": src[0], "dst": dst[0], "protocol": "udp"},
        "transport": {"src_port": src[1], "dst_port": dst[1]},
        "dns": section,
        "packet_metadata": meta,
    }


def _directions(messages: list | dict) -> list[str]:
    return [m.direction for m in protocol_conversation(_dns(), messages, "udp")]


class TestWhereADirectionComesFrom(unittest.TestCase):

    def test_a_bare_section_goes_client_to_server(self) -> None:
        self.assertEqual(_directions([_QUERY, _RESPONSE]), ["c2s", "c2s"])

    def test_a_wrapped_section_says_its_direction_beside_it(self) -> None:
        given = [{"dns": _QUERY}, {"dns": _RESPONSE, "direction": "s2c"}]
        self.assertEqual(_directions(given), ["c2s", "s2c"])

    def test_a_packet_says_its_direction_in_its_metadata(self) -> None:
        client, server = ("10.0.0.2", 54321), ("10.0.0.1", 53)
        # The metadata wins over the ports, which say the opposite here.
        given = [_packet(_QUERY, server, client, "c2s"),
                 _packet(_RESPONSE, client, server, "s2c")]
        self.assertEqual(_directions(given), ["c2s", "s2c"])

    def test_a_parsed_packet_is_read_by_the_protocol_port(self) -> None:
        """`packeteer parse` writes no direction: the side on port 53 is the server."""
        client, server = ("10.0.0.2", 54321), ("10.0.0.1", 53)
        # The response first, so a first-sender rule would get it wrong.
        given = {"packets": [_packet(_RESPONSE, server, client),
                             _packet(_QUERY, client, server)]}
        self.assertEqual(_directions(given), ["s2c", "c2s"])

    def test_without_a_protocol_port_the_first_sender_is_the_client(self) -> None:
        a, b = ("10.0.0.2", 40000), ("10.0.0.1", 40001)
        given = [_packet(_QUERY, a, b), _packet(_RESPONSE, b, a), _packet(_QUERY, a, b)]
        self.assertEqual(_directions(given), ["c2s", "s2c", "c2s"])

    def test_the_first_sender_counts_packets_with_no_message(self) -> None:
        """For TCP the client sent the SYN, which carries no section."""
        a, b = ("10.0.0.2", 40000), ("10.0.0.1", 40001)
        syn = _packet(_QUERY, a, b)
        del syn["dns"]
        given = [syn, _packet(_RESPONSE, b, a)]
        self.assertEqual(_directions(given), ["s2c"])

    def test_a_bad_direction_is_refused(self) -> None:
        for given, where in (
            ([{"dns": _QUERY, "direction": "up"}], "'direction'"),
            ([_packet(_QUERY, ("a", 1), ("b", 53), "sideways")], "packet_metadata.direction"),
        ):
            with self.subTest(where=where), self.assertRaises(ValueError) as caught:
                _directions(given)
            self.assertIn(f"message 0: {where} must be 'c2s' or 's2c'", str(caught.exception))

    def test_a_misspelt_key_beside_a_section_is_refused(self) -> None:
        """It was dropped in silence before #195."""
        with self.assertRaises(ValueError) as caught:
            _directions([{"dns": _QUERY, "drection": "s2c"}])
        self.assertIn("unknown key 'drection' beside the 'dns' section", str(caught.exception))

    def test_messages_take_no_direction_key(self) -> None:
        """`protocol_messages` callers read the direction from the message itself."""
        with self.assertRaises(ValueError) as caught:
            protocol_messages(_dns(), [{"dns": _QUERY, "direction": "c2s"}], "udp")
        self.assertIn("unknown key 'direction'", str(caught.exception))

    def test_the_conversation_is_encoded_and_labelled(self) -> None:
        messages = protocol_conversation(_dns(), [_QUERY], "udp")
        self.assertEqual(messages[0].label, "dns[0]")
        self.assertEqual(messages[0].data, _dns().encode(_dns().from_spec(_QUERY), "udp"))


class TestAPayloadFnRefusesAReply(unittest.TestCase):

    def test_a_reply_is_refused_naming_the_issue(self) -> None:
        given = [{"dns": _QUERY}, {"dns": _RESPONSE, "direction": "s2c"}]
        with self.assertRaises(ValueError) as caught:
            protocol_payload_fn(_dns(), given, "tcp")
        self.assertIn("message 1 travels server to client", str(caught.exception))
        self.assertIn("issues/198", str(caught.exception))

    def test_client_messages_are_unchanged(self) -> None:
        fn = protocol_payload_fn(_dns(), [_QUERY, _RESPONSE], "udp")
        self.assertEqual(fn(1, "c2s"), _dns().encode(_dns().from_spec(_RESPONSE), "udp"))


def _stream(messages: list[AppMessage], count: int = 4, **config: object) -> list:
    return generate_udp_stream(
        client_ip="10.0.0.2", server_ip="10.0.0.1", server_port=53,
        client_mac="00:00:00:00:00:01", server_mac="00:00:00:00:00:02",
        num_data_packets=count,
        config=UDPStreamConfig(base_time=1_700_000_000.0, seed=1,
                               messages=messages, **config),
    ).packets


class TestTheGeneratorSendsEachWay(unittest.TestCase):

    def setUp(self) -> None:
        self.messages = [AppMessage("c2s", b"query", "q"), AppMessage("s2c", b"answer", "a")]

    def test_a_reply_leaves_from_the_server(self) -> None:
        packets = _stream(self.messages)
        self.assertEqual([p.direction for p in packets], ["c2s", "s2c", "c2s", "s2c"])
        reply = parse_packet(packets[1].raw)
        self.assertEqual((reply.ip.src, reply.transport.src_port), ("10.0.0.1", 53))
        self.assertEqual((reply.ip.dst, reply.transport.dst_port), ("10.0.0.2", 54321))
        self.assertEqual(reply.ethernet.src_mac, "00:00:00:00:00:02")
        self.assertEqual(reply.payload, b"answer")

    def test_a_short_list_repeats_and_labels_are_unchanged(self) -> None:
        packets = _stream(self.messages, count=3)
        self.assertEqual([p.label for p in packets], ["DATA[0]", "DATA[1]", "DATA[2]"])
        self.assertEqual(packets[2].payload_len, len(b"query"))

    def test_impairments_apply_in_both_directions(self) -> None:
        packets = _stream(self.messages, impairments=ImpairmentConfig(
            payload_corruption_probability=1.0))
        self.assertEqual({p.direction for p in packets}, {"c2s", "s2c"})
        self.assertTrue(all(p.label.startswith("CORRUPT[") for p in packets))

    def test_payload_fn_and_messages_are_refused_together(self) -> None:
        with self.assertRaises(ValueError):
            _stream(self.messages, payload_fn=lambda i, d: b"x")

    def test_an_empty_list_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            _stream([])


def _packeteer(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "packeteer", *args],
        capture_output=True, text=True, check=False,
    )


class TestTheIssuesAcceptance(unittest.TestCase):
    """A parsed DNS capture with queries and responses replays both ways."""

    _COMMON = ("--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1",
               "--server-port", "53", "--seed", "1", "--packets", "6")

    def setUp(self) -> None:
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)
        given = self.dir / "given.json"
        given.write_text(json.dumps([{"dns": _QUERY}, {"dns": _RESPONSE, "direction": "s2c"}]))
        capture = self.dir / "capture.pcap"
        done = _packeteer("stream", "--protocol", "udp", "--payload", "dns",
                          "--protocol-messages", str(given), *self._COMMON,
                          "--pcap", str(capture))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.parsed = self.dir / "parsed.json"
        done = _packeteer("parse", str(capture), "--output", str(self.parsed))
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_a_parsed_capture_replays_in_both_directions(self) -> None:
        out = self.dir / "replay.json"
        done = _packeteer("stream", "--protocol", "udp", "--payload", "dns",
                          "--protocol-messages", str(self.parsed), *self._COMMON,
                          "--json", str(out))
        self.assertEqual(done.returncode, 0, done.stderr)
        packets = json.loads(out.read_text())["packets"]
        self.assertEqual([p["packet_metadata"]["direction"] for p in packets],
                         ["c2s", "s2c"] * 3)
        for p in packets:
            if p["packet_metadata"]["direction"] == "s2c":
                self.assertEqual(p["network"]["src"], "10.0.0.1")
                self.assertEqual(p["transport"]["src_port"], 53)

    def test_the_same_capture_over_tcp_is_refused(self) -> None:
        done = _packeteer("stream", "--protocol", "tcp", "--payload", "dns",
                          "--protocol-messages", str(self.parsed), *self._COMMON,
                          "--json", str(self.dir / "tcp.json"))
        self.assertEqual(done.returncode, 1)
        self.assertIn("message 1 travels server to client", done.stderr)
        self.assertIn("issues/198", done.stderr)


if __name__ == "__main__":
    unittest.main()
