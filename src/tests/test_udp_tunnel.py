"""A UDP tunnel whose outer payload the caller's code computes (#197).

The wrapper is the caller's object; packeteer hands it each inner packet
once per time it is sent, in wire order, and builds the outer datagrams it
returns.  These tests hold the four semantics the issue asks for, with a
recording wrapper and with the example in ``examples/udp_tunnel``.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import re
import tempfile
import textwrap
import unittest
from io import StringIO
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate import (
    TCPStreamConfig,
    UDPStreamConfig,
    UDPTunnel,
    generate_tcp_stream,
    generate_udp_stream,
    load_wrapper,
    tunnel_stream,
)
from packeteer.generate.impairments import ImpairmentConfig
from packeteer.generate.payloads.base import AppMessage
from packeteer.parse import parse_packet
from packeteer.pcap import read_pcap

_EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "udp_tunnel" / "xor_seal.py"
_SRC, _DST, _PORT = "198.51.100.7", "203.0.113.9", 51820

#: An outer datagram's label: ``TUNNEL[<inner label>]``, then ``+N`` for the
#: further datagrams of one call.
_TUNNEL_LABEL = re.compile(r"^TUNNEL\[(.*)\](?:\+\d+)?$")


def _example() -> ModuleType:
    """Import the example module, for its `open_datagram`."""
    spec = importlib.util.spec_from_file_location("xor_seal_under_test", _EXAMPLE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Recorder:
    """Seal nothing: prefix a counter, and remember every call."""

    def __init__(self, extra: list[tuple[str, bytes]] | None = None) -> None:
        self.calls: list[tuple[bytes, str, float]] = []
        self.extra = extra or []

    def wrap(self, inner: bytes, direction: str, timestamp: float) -> list[tuple[str, bytes]]:
        self.calls.append((inner, direction, timestamp))
        extra, self.extra = self.extra, []
        return [*extra, (direction, len(self.calls).to_bytes(4, "big") + inner)]


def _lossy_tcp(seed: int = 3) -> list:
    return generate_tcp_stream(
        client_ip="10.0.0.2", server_ip="10.0.0.1", num_data_packets=20,
        include_ethernet=False,
        config=TCPStreamConfig(seed=seed, base_time=1_700_000_000.0,
                               packet_loss_probability=0.3, retransmit_lost=True),
    )


def _tunnel(wrapper: object, **kw: object) -> UDPTunnel:
    return UDPTunnel(src_ip=_SRC, dst_ip=_DST, port=_PORT, wrapper=wrapper, **kw)


class TestWireOrder(unittest.TestCase):
    """1: each inner packet once per time it is sent, in wire order."""

    def test_every_packet_sent_is_wrapped_once_in_order(self) -> None:
        inner = _lossy_tcp()
        recorder = Recorder()
        tunnel_stream(inner, _tunnel(recorder), seed=3)
        sent = sorted(inner.packets, key=lambda p: (p.ts_sec, p.ts_usec))
        self.assertEqual([c[0] for c in recorder.calls], [p.raw for p in sent])
        times = [c[2] for c in recorder.calls]
        self.assertEqual(times, sorted(times))

    def test_a_retransmission_is_wrapped_again_and_a_loss_never(self) -> None:
        inner = _lossy_tcp()
        labels = [p.label for p in inner.packets]
        self.assertTrue([lbl for lbl in labels if lbl.startswith("RETRANS[")],
                        "the seed should give a loss that is recovered")
        out = tunnel_stream(inner, _tunnel(Recorder()), seed=3)
        outer = [p.label for p in out.packets]
        for label in labels:
            self.assertIn(f"TUNNEL[{label}]", outer)
        self.assertEqual(len(outer), len(labels))

    def test_the_timestamp_is_the_inner_packets(self) -> None:
        inner = _lossy_tcp()
        recorder = Recorder()
        tunnel_stream(inner, _tunnel(recorder))
        first = min(inner.packets, key=lambda p: (p.ts_sec, p.ts_usec))
        self.assertEqual(recorder.calls[0][2], first.ts_sec + first.ts_usec / 1_000_000)


class TestOuterImpairments(unittest.TestCase):
    """2: outer impairments apply after wrapping, to the sealed bytes."""

    def test_corruption_breaks_exactly_the_corrupted_datagrams(self) -> None:
        example = _example()
        out = tunnel_stream(
            _lossy_tcp(), _tunnel(load_wrapper(_EXAMPLE, {"key": "k"})), seed=3,
            impairments=ImpairmentConfig(payload_corruption_probability=0.3),
        )
        corrupted = 0
        for pkt in out.packets:
            payload = parse_packet(pkt.raw).payload
            if pkt.label.startswith("CORRUPT["):
                corrupted += 1
                with self.assertRaises(ValueError):
                    example.open_datagram(b"k", payload, pkt.direction)
            else:
                example.open_datagram(b"k", payload, pkt.direction)
        self.assertGreater(corrupted, 0)

    def test_a_sealed_datagram_opens_to_its_inner_packet(self) -> None:
        """In wire order: labels repeat in TCP (every bare ACK is `ACK`)."""
        example = _example()
        inner = _lossy_tcp()
        out = tunnel_stream(inner, _tunnel(load_wrapper(_EXAMPLE, {"key": "k"})))
        opened = [example.open_datagram(b"k", parse_packet(p.raw).payload, p.direction)
                  for p in out.packets]
        sent = sorted(inner.packets, key=lambda p: (p.ts_sec, p.ts_usec))
        self.assertEqual([o for o in opened if o is not None], [p.raw for p in sent])

    def test_outer_loss_does_not_change_what_the_wrapper_sees(self) -> None:
        clean, lossy = Recorder(), Recorder()
        tunnel_stream(_lossy_tcp(), _tunnel(clean), seed=3)
        out = tunnel_stream(_lossy_tcp(), _tunnel(lossy), seed=3,
                            impairments=ImpairmentConfig(packet_loss_probability=0.5))
        self.assertEqual(clean.calls, lossy.calls)
        self.assertLess(len(out.packets), len(clean.calls))


class TestDirection(unittest.TestCase):
    """3: a returned direction maps to the endpoints."""

    def test_each_direction_leaves_from_its_endpoint(self) -> None:
        inner = generate_udp_stream(
            client_ip="10.0.0.2", server_ip="10.0.0.1", num_data_packets=2,
            include_ethernet=False,
            config=UDPStreamConfig(base_time=1_700_000_000.0, messages=[
                AppMessage("c2s", b"query", ""), AppMessage("s2c", b"reply", "")]),
        )
        out = tunnel_stream(inner, _tunnel(Recorder(), src_port=40000))
        ends = [(p.direction, parse_packet(p.raw)) for p in out.packets]
        (d0, q0), (d1, q1) = ends
        self.assertEqual((d0, q0.ip.src, q0.transport.src_port, q0.ip.dst, q0.transport.dst_port),
                         ("c2s", _SRC, 40000, _DST, _PORT))
        self.assertEqual((d1, q1.ip.src, q1.transport.src_port, q1.ip.dst, q1.transport.dst_port),
                         ("s2c", _DST, _PORT, _SRC, 40000))

    def test_the_source_port_defaults_to_the_port(self) -> None:
        out = tunnel_stream(_lossy_tcp(), _tunnel(Recorder()))
        self.assertEqual(parse_packet(out.packets[0].raw).transport.src_port, _PORT)

    def test_a_reply_the_wrapper_adds_goes_its_own_way(self) -> None:
        recorder = Recorder(extra=[("c2s", b"init"), ("s2c", b"response")])
        out = tunnel_stream(_lossy_tcp(), _tunnel(recorder))
        first = out.packets[:3]
        self.assertEqual([p.direction for p in first], ["c2s", "s2c", "c2s"])
        self.assertEqual(parse_packet(first[1].raw).ip.src, _DST)
        self.assertEqual([p.label for p in first],
                         ["TUNNEL[SYN]", "TUNNEL[SYN]+1", "TUNNEL[SYN]+2"])
        stamps = [p.ts_sec * 1_000_000 + p.ts_usec for p in first]
        self.assertEqual(stamps, [stamps[0], stamps[0] + 1, stamps[0] + 2])

    def test_an_empty_return_sends_nothing(self) -> None:
        class Swallow:
            def wrap(self, inner: bytes, direction: str, timestamp: float) -> list:
                return []
        self.assertEqual(tunnel_stream(_lossy_tcp(), _tunnel(Swallow())).packets, [])


class TestReproducible(unittest.TestCase):
    """4: seeded and reproducible."""

    def test_the_same_seed_gives_the_same_datagrams(self) -> None:
        def run() -> list:
            return tunnel_stream(
                _lossy_tcp(), _tunnel(load_wrapper(_EXAMPLE)), seed=3,
                impairments=ImpairmentConfig(packet_loss_probability=0.2,
                                             payload_corruption_probability=0.2,
                                             reorder_probability=0.2,
                                             duplicate_probability=0.2),
            ).to_pcap_tuples()
        self.assertEqual(run(), run())


class TestRefusals(unittest.TestCase):

    def test_an_inner_packet_with_a_link_layer(self) -> None:
        inner = generate_udp_stream(client_ip="10.0.0.2", server_ip="10.0.0.1")
        with self.assertRaisesRegex(ValueError, "include_ethernet=False"):
            tunnel_stream(inner, _tunnel(Recorder()))

    def test_a_wrapper_that_returns_the_wrong_shape(self) -> None:
        for result, message in (
            (b"sealed", "must be a sequence"),
            ([("up", b"x")], "direction must be 'c2s' or 's2c'"),
            ([("c2s", "text")], "payload must be bytes"),
            ([("c2s",)], "must be a \\(direction, payload\\) pair"),
        ):
            class Wrong:
                def wrap(self, inner: bytes, direction: str, timestamp: float,
                         result: object = result) -> object:
                    return result
            with self.subTest(result=result), self.assertRaisesRegex(ValueError, message):
                tunnel_stream(_lossy_tcp(), _tunnel(Wrong()))


class TestLoadWrapper(unittest.TestCase):

    def _module(self, body: str) -> Path:
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, directory, True)
        path = directory / "wrapper.py"
        path.write_text(textwrap.dedent(body))
        return path

    def test_the_arguments_reach_the_factory(self) -> None:
        wrapper = load_wrapper(_EXAMPLE, {"key": "abc", "rekey_after": "5"})
        self.assertEqual((wrapper.key, wrapper.rekey_after), (b"abc", 5))

    def test_each_load_is_a_fresh_wrapper(self) -> None:
        self.assertIsNot(load_wrapper(_EXAMPLE), load_wrapper(_EXAMPLE))

    def test_what_is_refused_names_the_file(self) -> None:
        for body, message in (
            ("x = 1\n", "defines no make_wrapper"),
            ("def make_wrapper(args):\n    raise KeyError('key')\n",
             "make_wrapper raised KeyError"),
            ("def make_wrapper(args):\n    return 42\n", "has no wrap"),
            ("raise RuntimeError('boom')\n", "failed while being imported"),
        ):
            with self.subTest(message=message):
                path = self._module(body)
                with self.assertRaisesRegex(ValueError, message) as caught:
                    load_wrapper(path)
                self.assertIn(str(path), str(caught.exception))

    def test_a_missing_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "no tunnel module"):
            load_wrapper("/nonexistent/wrapper.py")


class TestTheCLI(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        args = argparse.Namespace(
            config=None, client_ip="10.0.0.2", server_ip="10.1.0.1",
            pcap=None, pcapng=None, json=None, payload=None, packets=6, seed=7,
            udp_tunnel=[_SRC, _DST], tunnel_port=_PORT,
            tunnel_module=str(_EXAMPLE), tunnel_arg=["key=k"],
        )
        for key, value in over.items():
            setattr(args, key, value)
        return args

    def _write(self, **over: object) -> Path:
        fd, out = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        self.addCleanup(os.remove, out)
        with patch("sys.stdout", new=StringIO()):
            cli._cmd_stream(self._args(pcap=out, **over))
        return Path(out)

    def _refused(self, **over: object) -> str:
        err = StringIO()
        with patch("sys.stdout", new=StringIO()), patch("sys.stderr", new=err), \
                self.assertRaises(SystemExit):
            cli._cmd_stream(self._args(pcap=os.devnull, **over))
        return err.getvalue()

    def _outer(self, path: Path) -> list:
        return [parse_packet(raw) for raw, _, _ in read_pcap(path=path).packets]

    def test_every_payload_goes_through(self) -> None:
        for name, over in {"tcp": {}, "udp": {"protocol": "udp"},
                           "http": {"payload": "http", "requests": 2},
                           "vpn": {"payload": "vpn", "vpn_epochs": 1},
                           "sessions": {"sessions": 3}}.items():
            with self.subTest(payload=name):
                packets = self._outer(self._write(**over))
                self.assertTrue(packets)
                self.assertTrue(all(_PORT in (p.transport.src_port, p.transport.dst_port)
                                    for p in packets))
                self.assertTrue(all({p.ip.src, p.ip.dst} == {_SRC, _DST} for p in packets))

    def test_a_seeded_run_reproduces_as_a_file(self) -> None:
        over = {"tunnel_corruption": 0.3, "tunnel_reorder": 0.3}
        self.assertEqual(self._write(**over).read_bytes(), self._write(**over).read_bytes())

    def test_layer_two_tags_go_on_the_outer_packet(self) -> None:
        packets = self._outer(self._write(vlan=7))
        self.assertTrue(all(p.ethernet.vlan_tag.vid == 7 for p in packets))

    def test_the_refusals(self) -> None:
        for over, message in (
            ({"duplicate_probability": 0.3}, "use --tunnel-duplicate"),
            ({"gre": ["192.0.2.1", "192.0.2.2"]}, "--gre, --udp-tunnel"),
            ({"tunnel_port": None}, "--udp-tunnel needs --tunnel-port"),
            ({"tunnel_module": None}, "--udp-tunnel needs --tunnel-module"),
            ({"tunnel_arg": ["novalue"]}, "--tunnel-arg must be KEY=VALUE"),
            ({"udp_tunnel": None, "tunnel_corruption": 0.3}, "--tunnel-port, --tunnel-module"),
            ({"tunnel_module": "/nonexistent.py"}, "no tunnel module"),
        ):
            with self.subTest(message=message):
                self.assertIn(message, self._refused(**over))


if __name__ == "__main__":
    unittest.main()
