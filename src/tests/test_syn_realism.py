"""Generated handshakes advertise what a real client does (#88)."""
from __future__ import annotations

import argparse
import os
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

import packeteer.__main__ as cli
from packeteer.generate.payloads.http import HTTPRestConfig, generate_http_stream
from packeteer.generate.session_mix import CombinedStream
from packeteer.generate.tcp import (
    DEFAULT_MSS,
    TCPOptions,
    _build_options,
    default_syn_options,
)
from packeteer.generate.tcp_stream import (
    TCPStream,
    TCPStreamConfig,
    generate_tcp_stream,
)
from packeteer.parse import parse_packet
from packeteer.parse.tcp import _parse_options
from packeteer.pcap import read_pcap

_BASE_TIME = 1_700_000_000.0


def _syn(stream: TCPStream | CombinedStream) -> TCPOptions | None:
    """Return the parsed options on the first packet of *stream*."""
    return parse_packet(stream.packets[0].raw).transport.options


class TestOptionAlignment(unittest.TestCase):
    """NOP padding goes ahead of the option it aligns, not after everything."""

    def test_timestamps_get_the_rfc_7323_layout(self) -> None:
        encoded = _build_options(TCPOptions(timestamps=(0x11223344, 0x55667788)))
        self.assertEqual(encoded[:2], b"\x01\x01")
        self.assertEqual(encoded[2], 8)

    def test_timestamp_fields_land_aligned(self) -> None:
        for preceding in (TCPOptions(), TCPOptions(mss=1460),
                          TCPOptions(mss=1460, window_scale=7),
                          TCPOptions(mss=1460, sack_permitted=True)):
            preceding.timestamps = (1, 2)
            with self.subTest(opts=preceding):
                encoded = _build_options(preceding)
                start = encoded.index(b"\x08\x0a")
                self.assertEqual((start + 2) % 4, 0)   # TSval on a boundary

    def test_sack_blocks_are_aligned_too(self) -> None:
        encoded = _build_options(TCPOptions(sack_blocks=[(1, 2)]))
        self.assertEqual(encoded[:2], b"\x01\x01")
        self.assertEqual(encoded[2], 5)

    def test_region_is_always_a_multiple_of_four(self) -> None:
        for opts in (TCPOptions(mss=1460), default_syn_options(),
                     TCPOptions(timestamps=(1, 2)), TCPOptions(window_scale=7),
                     TCPOptions(mss=1460, sack_blocks=[(1, 2), (3, 4)])):
            with self.subTest(opts=opts):
                self.assertEqual(len(_build_options(opts)) % 4, 0)

    def test_encoded_layout_survives_a_decode(self) -> None:
        opts = default_syn_options()
        self.assertEqual(_parse_options(_build_options(opts)).mss, opts.mss)


class TestDefaultSynOptions(unittest.TestCase):

    def test_a_modern_client_set(self) -> None:
        opts = default_syn_options()
        self.assertEqual(opts.mss, DEFAULT_MSS)
        self.assertTrue(opts.sack_permitted)
        self.assertIsNotNone(opts.window_scale)

    def test_timestamps_are_not_advertised(self) -> None:
        """Only the handshake carries options, so advertising them would lie."""
        self.assertIsNone(default_syn_options().timestamps)

    def test_each_call_returns_a_fresh_object(self) -> None:
        first = default_syn_options()
        first.mss = 1
        self.assertEqual(default_syn_options().mss, DEFAULT_MSS)

    def test_low_level_syn_carries_them_by_default(self) -> None:
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=2,
            config=TCPStreamConfig(seed=1, base_time=_BASE_TIME),
        )
        self.assertIsNotNone(_syn(stream))

    def test_bare_syn_still_available(self) -> None:
        stream = generate_tcp_stream(
            client_ip="10.0.0.1", server_ip="10.0.0.2", num_data_packets=2,
            config=TCPStreamConfig(seed=1, base_time=_BASE_TIME,
                                   client_options=None, server_options=None),
        )
        self.assertIsNone(_syn(stream))

    def test_payload_path_syn_carries_them_too(self) -> None:
        """The path that could not carry options at all before this."""
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1, seed=1,
            base_time=_BASE_TIME,
        )
        self.assertIsNotNone(_syn(stream))

    def test_payload_path_bare_syn(self) -> None:
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1, seed=1,
            base_time=_BASE_TIME, config=HTTPRestConfig(syn_options=None),
        )
        self.assertIsNone(_syn(stream))


class TestAdvertisedMssMatchesSegmentation(unittest.TestCase):
    """A capture must not contradict its own segmentation."""

    def test_mss_follows_the_segment_size(self) -> None:
        for mss in (1460, 512, 128):
            with self.subTest(mss=mss):
                stream = generate_http_stream(
                    client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1,
                    mss=mss, seed=1, base_time=_BASE_TIME,
                )
                self.assertEqual(_syn(stream).mss, mss)

    def test_an_explicit_mss_is_not_overridden(self) -> None:
        stream = generate_http_stream(
            client_ip="10.0.0.1", server_ip="10.1.0.1", requests=1, mss=128,
            seed=1, base_time=_BASE_TIME,
            config=HTTPRestConfig(syn_options=TCPOptions(mss=999)),
        )
        self.assertEqual(_syn(stream).mss, 999)


class TestCmdStreamSynOptions(unittest.TestCase):

    def _args(self, **over: object) -> argparse.Namespace:
        ns = argparse.Namespace(
            config=None, client_ip="10.0.0.1", server_ip="10.0.0.2",
            pcap=None, pcapng=None, json=None, seed=1,
        )
        for k, v in over.items():
            setattr(ns, k, v)
        return ns

    def _first_packet(self, **over: object) -> bytes:
        fd, path = tempfile.mkstemp(suffix=".pcap")
        os.close(fd)
        try:
            with patch("sys.stdout", new=StringIO()):
                cli._cmd_stream(self._args(pcap=path, **over))
            return read_pcap(path=path).packets[0][0]
        finally:
            os.remove(path)

    def test_default_syn_has_options(self) -> None:
        raw = self._first_packet(packets=2)
        self.assertIsNotNone(parse_packet(raw).transport.options)

    def test_no_tcp_options_gives_a_bare_syn(self) -> None:
        raw = self._first_packet(packets=2, no_tcp_options=True)
        self.assertIsNone(parse_packet(raw).transport.options)

    def test_mss_flag_reaches_the_advertised_value(self) -> None:
        raw = self._first_packet(payload="http", requests=1, mss=512)
        self.assertEqual(parse_packet(raw).transport.options.mss, 512)


if __name__ == "__main__":
    unittest.main()
