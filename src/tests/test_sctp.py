"""Tests for SCTP support: builder, parser, to_config, and CLI round-trips."""
from __future__ import annotations

import json
import struct

from packeteer.generate import PacketBuilder
from packeteer.generate.checksum import crc32c
from packeteer.generate.sctp import (
    IPPROTO_SCTP,
    SCTP_DATA_FLAG_BEGINNING,
    SCTP_DATA_FLAG_ENDING,
    SCTP_DATA_FLAG_UNORDERED,
    SCTPAbortChunk,
    SCTPCookieAckChunk,
    SCTPCookieEchoChunk,
    SCTPDataChunk,
    SCTPErrorChunk,
    SCTPGenericChunk,
    SCTPHeader,
    SCTPHeartbeatAckChunk,
    SCTPHeartbeatChunk,
    SCTPInitAckChunk,
    SCTPInitChunk,
    SCTPSackChunk,
    SCTPShutdownAckChunk,
    SCTPShutdownChunk,
    SCTPShutdownCompleteChunk,
    _build_sctp_packet,
    _pad4,
)
from packeteer.parse.core import parse_packet
from packeteer.parse.sctp import packet_parser as sctp_parser
from packeteer.parse.to_config import update_config
from packeteer.pcap import LINKTYPE_RAW

# ── Group 1: crc32c ───────────────────────────────────────────────────────────

class TestCrc32c:
    def test_known_value(self):
        # CRC-32c of empty bytes
        assert crc32c(b"") == 0x00000000

    def test_known_value_hello(self):
        # Known CRC-32c of b"123456789" is 0xE3069283
        assert crc32c(b"123456789") == 0xE3069283

    def test_returns_int(self):
        v = crc32c(b"test")
        assert isinstance(v, int)
        assert 0 <= v <= 0xFFFFFFFF

    def test_different_inputs_differ(self):
        assert crc32c(b"abc") != crc32c(b"abd")

    def test_all_zeros_nonzero(self):
        # All-zero bytes should produce a non-trivial checksum
        assert crc32c(b"\x00" * 16) != 0


# ── Group 2: _build_sctp_packet common header ──────────────────────────────────

class TestBuildSctpPacketHeader:
    def _make(
        self,
        src: int = 1234,
        dst: int = 9999,
        tag: int = 0xDEADBEEF,
        chunks: list[object] | None = None,
    ) -> bytes:
        hdr = SCTPHeader(src_port=src, dst_port=dst, verification_tag=tag,
                         chunks=chunks or [])
        return _build_sctp_packet(hdr)

    def test_minimum_length(self):
        raw = self._make()
        # 12 common header + at least 16 for default DATA chunk
        assert len(raw) >= 12 + 16

    def test_src_dst_ports(self):
        raw = self._make(src=1111, dst=2222)
        src, dst = struct.unpack("!HH", raw[:4])
        assert src == 1111
        assert dst == 2222

    def test_verification_tag(self):
        raw = self._make(tag=0xCAFEBABE)
        (tag,) = struct.unpack("!I", raw[4:8])
        assert tag == 0xCAFEBABE

    def test_checksum_field_nonzero(self):
        raw = self._make()
        (cksum,) = struct.unpack("!I", raw[8:12])
        assert cksum != 0

    def test_checksum_correct(self):
        raw = self._make()
        # Zero checksum field, recompute, compare
        zeroed = raw[:8] + b"\x00\x00\x00\x00" + raw[12:]
        assert crc32c(zeroed) == struct.unpack("!I", raw[8:12])[0]

    def test_empty_chunks_defaults_to_data(self):
        raw = self._make(chunks=[])
        # Should still produce a valid packet (default DATA chunk)
        assert len(raw) >= 12 + 16


# ── Group 3: DATA chunk encoding ─────────────────────────────────────────────

class TestDataChunk:
    def _build(
        self,
        tsn: int = 0,
        stream_id: int = 0,
        stream_seq: int = 0,
        ppid: int = 0,
        data: bytes = b"",
        flags: int = SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING,
    ) -> bytes:
        hdr = SCTPHeader(chunks=[SCTPDataChunk(
            tsn=tsn, stream_id=stream_id, stream_seq=stream_seq,
            ppid=ppid, data=data, flags=flags,
        )])
        return _build_sctp_packet(hdr)

    def test_chunk_type_byte(self):
        raw = self._build()
        assert raw[12] == 0  # DATA = type 0

    def test_flags_byte(self):
        raw = self._build(flags=SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING)
        assert raw[13] == 0x03

    def test_length_field_no_payload(self):
        raw = self._build(data=b"")
        length = struct.unpack("!H", raw[14:16])[0]
        assert length == 16  # 4 chunk header + 12 fixed DATA fields

    def test_length_field_with_payload(self):
        raw = self._build(data=b"hello")
        length = struct.unpack("!H", raw[14:16])[0]
        assert length == 16 + 5

    def test_tsn_field(self):
        raw = self._build(tsn=0xABCD1234)
        (tsn,) = struct.unpack("!I", raw[16:20])
        assert tsn == 0xABCD1234

    def test_payload_bytes(self):
        payload = b"hello sctp"
        raw = self._build(data=payload)
        assert raw[28:28 + len(payload)] == payload

    def test_chunk_padded_to_4_bytes(self):
        # payload of 3 bytes → chunk length = 19 → padded to 20
        raw = self._build(data=b"abc")
        assert len(raw) % 4 == 0

    def test_unordered_flag(self):
        raw = self._build(flags=SCTP_DATA_FLAG_UNORDERED |
                          SCTP_DATA_FLAG_BEGINNING | SCTP_DATA_FLAG_ENDING)
        assert raw[13] & SCTP_DATA_FLAG_UNORDERED


# ── Group 4: INIT / INIT ACK encoding ────────────────────────────────────────

class TestInitChunks:
    def _build_init(self, chunk: object) -> bytes:
        return _build_sctp_packet(SCTPHeader(chunks=[chunk]))

    def test_init_chunk_type(self):
        raw = self._build_init(SCTPInitChunk(initiate_tag=1))
        assert raw[12] == 1

    def test_init_ack_chunk_type(self):
        raw = self._build_init(SCTPInitAckChunk(initiate_tag=2))
        assert raw[12] == 2

    def test_init_fixed_fields(self):
        raw = self._build_init(SCTPInitChunk(
            initiate_tag=0x11223344, a_rwnd=65536,
            outbound_streams=2, inbound_streams=4, initial_tsn=100,
        ))
        tag, rwnd, out, ins, tsn = struct.unpack("!IIHHI", raw[16:32])
        assert tag == 0x11223344
        assert rwnd == 65536
        assert out == 2
        assert ins == 4
        assert tsn == 100

    def test_init_params_appended(self):
        params = b"\x00\x0c\x00\x04"  # example TLV
        raw = self._build_init(SCTPInitChunk(params=params))
        # chunk value starts at offset 16; fixed fields are 16 bytes; params follow
        assert raw[32:32 + len(params)] == params


# ── Group 5: SACK encoding ────────────────────────────────────────────────────

class TestSackChunk:
    def _build(
        self,
        cum: int = 0,
        rwnd: int = 0,
        gaps: list[object] | None = None,
        dups: list[object] | None = None,
    ) -> bytes:
        return _build_sctp_packet(SCTPHeader(chunks=[SCTPSackChunk(
            cum_tsn_ack=cum, a_rwnd=rwnd,
            gap_ack_blocks=gaps or [], dup_tsns=dups or [],
        )]))

    def test_chunk_type(self):
        raw = self._build()
        assert raw[12] == 3

    def test_counts_zero(self):
        raw = self._build()
        n_gap, n_dup = struct.unpack("!HH", raw[24:28])
        assert n_gap == 0
        assert n_dup == 0

    def test_gap_blocks_encoded(self):
        raw = self._build(gaps=[(1, 3), (5, 7)])
        n_gap, n_dup = struct.unpack("!HH", raw[24:28])
        assert n_gap == 2
        s1, e1, s2, e2 = struct.unpack("!HHHH", raw[28:36])
        assert (s1, e1) == (1, 3)
        assert (s2, e2) == (5, 7)

    def test_dup_tsns_encoded(self):
        raw = self._build(dups=[100, 200])
        n_gap, n_dup = struct.unpack("!HH", raw[24:28])
        assert n_dup == 2
        t1, t2 = struct.unpack("!II", raw[28:36])
        assert t1 == 100
        assert t2 == 200


# ── Group 6: small/empty chunks ──────────────────────────────────────────────

class TestSmallChunks:
    def _type(self, chunk: object) -> int:
        raw = _build_sctp_packet(SCTPHeader(chunks=[chunk]))
        return raw[12]

    def test_heartbeat_type(self):
        assert self._type(SCTPHeartbeatChunk()) == 4

    def test_heartbeat_ack_type(self):
        assert self._type(SCTPHeartbeatAckChunk()) == 5

    def test_abort_type(self):
        assert self._type(SCTPAbortChunk()) == 6

    def test_shutdown_type(self):
        assert self._type(SCTPShutdownChunk()) == 7

    def test_shutdown_ack_type(self):
        assert self._type(SCTPShutdownAckChunk()) == 8

    def test_error_type(self):
        assert self._type(SCTPErrorChunk()) == 9

    def test_cookie_echo_type(self):
        assert self._type(SCTPCookieEchoChunk()) == 10

    def test_cookie_ack_type(self):
        assert self._type(SCTPCookieAckChunk()) == 11

    def test_shutdown_complete_type(self):
        assert self._type(SCTPShutdownCompleteChunk()) == 14

    def test_generic_chunk_type(self):
        assert self._type(SCTPGenericChunk(chunk_type=42, value=b"xy")) == 42

    def test_heartbeat_info_encoded(self):
        info = b"\xde\xad\xbe\xef"
        raw = _build_sctp_packet(SCTPHeader(chunks=[SCTPHeartbeatChunk(info=info)]))
        # chunk header at 12; type(1)+flags(1)+len(2) = 16 offset for value
        # value = param_type(2)+param_len(2)+info
        param_type, param_len = struct.unpack("!HH", raw[16:20])
        assert param_type == 1
        assert param_len == 4 + len(info)
        assert raw[20:20 + len(info)] == info

    def test_cookie_echo_data(self):
        cookie = b"\xaa\xbb\xcc\xdd"
        raw = _build_sctp_packet(SCTPHeader(chunks=[SCTPCookieEchoChunk(cookie=cookie)]))
        assert raw[16:16 + len(cookie)] == cookie

    def test_shutdown_cum_tsn(self):
        raw = _build_sctp_packet(SCTPHeader(chunks=[SCTPShutdownChunk(cum_tsn_ack=999)]))
        (tsn,) = struct.unpack("!I", raw[16:20])
        assert tsn == 999


# ── Group 7: multiple chunks in one packet ────────────────────────────────────

class TestMultipleChunks:
    def test_two_data_chunks(self):
        hdr = SCTPHeader(chunks=[
            SCTPDataChunk(tsn=0, data=b"first"),
            SCTPDataChunk(tsn=1, data=b"second"),
        ])
        raw = _build_sctp_packet(hdr)
        # Should have two distinct DATA chunks after the 12-byte header
        assert raw[12] == 0   # first chunk type
        # Find second chunk: first chunk length = 16+5 = 21, padded to 24
        offset2 = 12 + _pad4(21)
        assert raw[offset2] == 0  # second chunk type

    def test_checksum_covers_all_chunks(self):
        hdr = SCTPHeader(chunks=[
            SCTPDataChunk(tsn=0, data=b"a"),
            SCTPDataChunk(tsn=1, data=b"bb"),
        ])
        raw = _build_sctp_packet(hdr)
        zeroed = raw[:8] + b"\x00\x00\x00\x00" + raw[12:]
        assert crc32c(zeroed) == struct.unpack("!I", raw[8:12])[0]


# ── Group 8: PacketBuilder integration ────────────────────────────────────────

class TestBuilderIntegration:
    def test_basic_build(self):
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=1234, dst_port=9999, verification_tag=1,
                     chunks=[SCTPDataChunk(tsn=0, data=b"hi")])
               .build())
        assert len(pkt) > 12 + 12  # IP header + SCTP

    def test_ip_protocol_field(self):
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=1, dst_port=2)
               .build())
        assert pkt[9] == IPPROTO_SCTP  # IPv4 protocol field at offset 9

    def test_with_ethernet(self):
        pkt = (PacketBuilder()
               .ethernet()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=1, dst_port=2)
               .build())
        assert len(pkt) > 14 + 20 + 12

    def test_ipv6(self):
        pkt = (PacketBuilder()
               .ip(src="2001:db8::1", dst="2001:db8::2")
               .sctp(src_port=1, dst_port=2)
               .build())
        # IPv6 next header at offset 6
        assert pkt[6] == IPPROTO_SCTP

    def test_sctp_checksum_correct_in_full_packet(self):
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=1234, dst_port=5678, verification_tag=42,
                     chunks=[SCTPDataChunk(tsn=0, data=b"test")])
               .build())
        # SCTP starts after 20-byte IPv4 header
        sctp_raw = pkt[20:]
        zeroed = sctp_raw[:8] + b"\x00\x00\x00\x00" + sctp_raw[12:]
        expected = crc32c(zeroed)
        actual = struct.unpack("!I", sctp_raw[8:12])[0]
        assert actual == expected


# ── Group 9: parser round-trip ────────────────────────────────────────────────

class TestParser:
    def _roundtrip(self, chunks: list[object]) -> object:
        raw = _build_sctp_packet(SCTPHeader(
            src_port=1111, dst_port=2222, verification_tag=0x42,
            chunks=chunks,
        ))
        consumed, dst_port, hdr = sctp_parser(raw)
        return hdr

    def test_consumed_equals_input_length(self):
        raw = _build_sctp_packet(SCTPHeader(chunks=[SCTPDataChunk(tsn=0)]))
        consumed, _, _ = sctp_parser(raw)
        assert consumed == len(raw)

    def test_dst_port(self):
        hdr = self._roundtrip([SCTPDataChunk(tsn=0)])
        assert hdr.dst_port == 2222

    def test_src_port(self):
        hdr = self._roundtrip([SCTPDataChunk(tsn=0)])
        assert hdr.src_port == 1111

    def test_verification_tag(self):
        hdr = self._roundtrip([SCTPDataChunk(tsn=0)])
        assert hdr.verification_tag == 0x42

    def test_data_chunk_roundtrip(self):
        hdr = self._roundtrip([SCTPDataChunk(tsn=77, stream_id=3, ppid=99, data=b"payload")])
        assert len(hdr.chunks) == 1
        c = hdr.chunks[0]
        assert isinstance(c, SCTPDataChunk)
        assert c.tsn == 77
        assert c.stream_id == 3
        assert c.ppid == 99
        assert c.data == b"payload"

    def test_init_roundtrip(self):
        hdr = self._roundtrip([SCTPInitChunk(
            initiate_tag=0x1234, a_rwnd=65536,
            outbound_streams=4, inbound_streams=8, initial_tsn=10,
        )])
        c = hdr.chunks[0]
        assert isinstance(c, SCTPInitChunk)
        assert c.initiate_tag == 0x1234
        assert c.outbound_streams == 4

    def test_sack_roundtrip(self):
        hdr = self._roundtrip([SCTPSackChunk(
            cum_tsn_ack=500, a_rwnd=131072,
            gap_ack_blocks=[(1, 3)], dup_tsns=[99],
        )])
        c = hdr.chunks[0]
        assert isinstance(c, SCTPSackChunk)
        assert c.cum_tsn_ack == 500
        assert c.gap_ack_blocks == [(1, 3)]
        assert c.dup_tsns == [99]

    def test_shutdown_roundtrip(self):
        hdr = self._roundtrip([SCTPShutdownChunk(cum_tsn_ack=42)])
        c = hdr.chunks[0]
        assert isinstance(c, SCTPShutdownChunk)
        assert c.cum_tsn_ack == 42

    def test_cookie_echo_roundtrip(self):
        hdr = self._roundtrip([SCTPCookieEchoChunk(cookie=b"\xde\xad")])
        c = hdr.chunks[0]
        assert isinstance(c, SCTPCookieEchoChunk)
        assert c.cookie == b"\xde\xad"

    def test_multiple_chunks_roundtrip(self):
        hdr = self._roundtrip([
            SCTPDataChunk(tsn=0, data=b"a"),
            SCTPDataChunk(tsn=1, data=b"b"),
        ])
        assert len(hdr.chunks) == 2
        assert isinstance(hdr.chunks[0], SCTPDataChunk)
        assert isinstance(hdr.chunks[1], SCTPDataChunk)

    def test_generic_chunk_fallback(self):
        # Build a raw packet with an unknown chunk type (200)
        chunk_raw = struct.pack("!BBH", 200, 0, 8) + b"\x01\x02\x03\x04"
        common = struct.pack("!HHII", 10, 20, 0, 0)
        raw_pkt = common + chunk_raw
        zeroed = raw_pkt[:8] + b"\x00\x00\x00\x00" + raw_pkt[12:]
        cksum = crc32c(zeroed)
        raw_pkt = raw_pkt[:8] + struct.pack("!I", cksum) + raw_pkt[12:]
        _, _, hdr = sctp_parser(raw_pkt)
        assert len(hdr.chunks) == 1
        assert isinstance(hdr.chunks[0], SCTPGenericChunk)
        assert hdr.chunks[0].chunk_type == 200

    def test_too_short_returns_none(self):
        consumed, dst, hdr = sctp_parser(b"\x00" * 8)
        assert consumed == 0
        assert hdr is None


# ── Group 10: parse_packet integration ────────────────────────────────────────

class TestParsePacketIntegration:
    def test_sctp_detected_in_ipv4(self):
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=1, dst_port=2,
                     chunks=[SCTPDataChunk(tsn=0, data=b"hi")])
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_RAW)
        assert parsed.transport is not None
        from packeteer.generate.sctp import SCTPHeader as _SCTPHeader
        assert isinstance(parsed.transport, _SCTPHeader)

    def test_sctp_ports_parsed(self):
        pkt = (PacketBuilder()
               .ip(src="10.0.0.1", dst="10.0.0.2")
               .sctp(src_port=5000, dst_port=6000,
                     chunks=[SCTPDataChunk(tsn=0)])
               .build())
        parsed = parse_packet(pkt, link_type=LINKTYPE_RAW)
        assert parsed.transport.src_port == 5000
        assert parsed.transport.dst_port == 6000


# ── Group 11: to_config serialization ────────────────────────────────────────

class TestToConfig:
    def _config(self, chunks: list[object]) -> dict:
        raw = _build_sctp_packet(SCTPHeader(
            src_port=100, dst_port=200, verification_tag=0x99,
            chunks=chunks,
        ))
        _, _, hdr = sctp_parser(raw)
        cfg: dict = {}
        update_config(cfg, hdr)
        return cfg["transport"]

    def test_sctp_transport_key_present(self):
        cfg = self._config([SCTPDataChunk(tsn=0)])
        assert "src_port" in cfg
        assert "dst_port" in cfg
        assert "verification_tag" in cfg
        assert "chunks" in cfg

    def test_ports(self):
        cfg = self._config([SCTPDataChunk(tsn=0)])
        assert cfg["src_port"] == 100
        assert cfg["dst_port"] == 200

    def test_data_chunk_serialized(self):
        cfg = self._config([SCTPDataChunk(tsn=7, stream_id=2, ppid=5, data=b"\xAA\xBB")])
        c = cfg["chunks"][0]
        assert c["type"] == "data"
        assert c["tsn"] == 7
        assert c["stream_id"] == 2
        assert c["ppid"] == 5
        assert c["data"] == "aabb"

    def test_init_chunk_serialized(self):
        cfg = self._config([SCTPInitChunk(initiate_tag=0x1234, outbound_streams=3)])
        c = cfg["chunks"][0]
        assert c["type"] == "init"
        assert c["initiate_tag"] == 0x1234
        assert c["outbound_streams"] == 3

    def test_sack_chunk_serialized(self):
        cfg = self._config([SCTPSackChunk(cum_tsn_ack=10, gap_ack_blocks=[(1, 2)])])
        c = cfg["chunks"][0]
        assert c["type"] == "sack"
        assert c["cum_tsn_ack"] == 10
        assert c["gap_ack_blocks"] == [[1, 2]]

    def test_heartbeat_serialized(self):
        cfg = self._config([SCTPHeartbeatChunk(info=b"\x01\x02")])
        c = cfg["chunks"][0]
        assert c["type"] == "heartbeat"
        assert c["info"] == "0102"

    def test_cookie_echo_serialized(self):
        cfg = self._config([SCTPCookieEchoChunk(cookie=b"\xff\xee")])
        c = cfg["chunks"][0]
        assert c["type"] == "cookie_echo"
        assert c["cookie"] == "ffee"

    def test_json_serializable(self):
        cfg = self._config([SCTPDataChunk(tsn=0, data=b"test")])
        # Should not raise
        json.dumps(cfg)
