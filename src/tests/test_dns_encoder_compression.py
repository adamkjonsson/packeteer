"""packeteer emits DNS name compression when it generates (#131).

Fidelity was settled by #130 — `raw` carries a captured message's bytes,
because senders disagree about pointer targets.  This is about resemblance:
every message `stream` and `build` produced had its names written in full,
which no resolver does, so a decoder tested against packeteer's DNS had
never seen a pointer.  The #87 pattern.
"""
from __future__ import annotations

import struct
import unittest

from packeteer import protocols
from packeteer.generate import PacketBuilder
from packeteer.generate.dns import (
    DNS_CLASS_IN,
    DNS_TYPE_A,
    DNS_TYPE_CNAME,
    DNS_TYPE_MX,
    DNS_TYPE_NS,
    DNS_TYPE_PTR,
    DNS_TYPE_SOA,
    DNS_TYPE_TXT,
    DNSFlags,
    DNSMessage,
    DNSQuestion,
    DNSRDataA,
    DNSRDataCNAME,
    DNSRDataMX,
    DNSRDataNS,
    DNSRDataPTR,
    DNSRDataRaw,
    DNSRDataSOA,
    DNSRDataTXT,
    DNSResourceRecord,
    _build_dns_message,
    _build_dns_message_tcp,
)
from packeteer.parse import parse_packet
from packeteer.parse.dns import parse_dns_tcp, parse_dns_udp


def _rr(name: str, rtype: int, rdata: object) -> DNSResourceRecord:
    return DNSResourceRecord(name=name, rtype=rtype, rclass=DNS_CLASS_IN, ttl=60, rdata=rdata)


def _response() -> DNSMessage:
    """One of every compressible RDATA type, plus the ones that must not."""
    return DNSMessage(
        id=0x4242, flags=DNSFlags(qr=True, rd=True, ra=True),
        questions=[DNSQuestion("www.example.com.")],
        answers=[
            _rr("www.example.com.", DNS_TYPE_CNAME, DNSRDataCNAME("example.com.")),
            _rr("example.com.", DNS_TYPE_A, DNSRDataA("93.184.216.34")),
        ],
        authority=[
            _rr("example.com.", DNS_TYPE_NS, DNSRDataNS("ns1.example.com.")),
            _rr("example.com.", DNS_TYPE_SOA, DNSRDataSOA(
                "ns1.example.com.", "hostmaster.example.com.", 1, 2, 3, 4, 5)),
        ],
        additional=[
            _rr("example.com.", DNS_TYPE_MX, DNSRDataMX(10, "mail.example.com.")),
            _rr("4.3.2.1.in-addr.arpa.", DNS_TYPE_PTR, DNSRDataPTR("mail.example.com.")),
            _rr("example.com.", DNS_TYPE_TXT, DNSRDataTXT([b"v=spf1 -all"])),
            _rr("example.com.", 65, DNSRDataRaw(rtype=65, data=b"\x07example\x03com\x00")),
        ],
    )


def _pointers(message: bytes) -> list[int]:
    """Return the offset of every compression pointer, found by parsing.

    Walks the message the way a decoder does, so a `0xC0` byte inside RDATA
    that is not a pointer (the TXT string, say) is not counted.
    """
    found: list[int] = []
    pos = 12

    def skip_name() -> None:
        nonlocal pos
        while True:
            length = message[pos]
            if length & 0xC0 == 0xC0:
                found.append(pos)
                pos += 2
                return
            pos += 1 + length
            if length == 0:
                return

    qd, an, ns, ar = struct.unpack_from("!HHHH", message, 4)
    for _ in range(qd):
        skip_name()
        pos += 4
    for _ in range(an + ns + ar):
        skip_name()
        rtype, _, _, rdlength = struct.unpack_from("!HHIH", message, pos)
        pos += 10
        end = pos + rdlength
        if rtype in (DNS_TYPE_CNAME, DNS_TYPE_NS, DNS_TYPE_PTR):
            skip_name()
        elif rtype == DNS_TYPE_MX:
            pos += 2
            skip_name()
        elif rtype == DNS_TYPE_SOA:
            skip_name()
            skip_name()
        pos = end
    return found


class TestItCompresses(unittest.TestCase):

    def test_pointers_appear(self) -> None:
        message = _build_dns_message(_response())
        self.assertGreater(len(_pointers(message)), 5)

    def test_it_is_shorter_than_writing_names_in_full(self) -> None:
        full = _build_dns_message(_response(), compress=False)
        self.assertLess(len(_build_dns_message(_response())), len(full))

    def test_every_pointer_points_backwards(self) -> None:
        message = _build_dns_message(_response())
        for at in _pointers(message):
            target = struct.unpack_from("!H", message, at)[0] & 0x3FFF
            self.assertLess(target, at)

    def test_it_points_at_the_longest_suffix(self) -> None:
        """The whole answer name is a pointer to the question name at 12."""
        message = _build_dns_message(_response())
        self.assertEqual(message[12 + 21:12 + 23], b"\xc0\x0c")

    def test_rdata_names_compress_for_the_rfc_1035_types(self) -> None:
        """CNAME, NS, PTR, MX and SOA carry names; every one is compressed."""
        message = _build_dns_message(_response())
        full = _build_dns_message(_response(), compress=False)
        # Past the question, and short of the raw type-65 RDATA at the very
        # end, which carries the literal name because it must (below).
        self.assertNotIn(b"\x07example\x03com\x00", message[12 + 21:-14],
                         "example.com is never written out a second time")
        self.assertIn(b"\x07example\x03com\x00", full[12 + 21:-14])

    def test_rdata_that_must_not_compress_is_untouched(self) -> None:
        """RFC 3597 §4: TXT strings and unknown-type RDATA are bytes."""
        message = _build_dns_message(_response())
        self.assertIn(b"\x0bv=spf1 -all", message)
        self.assertIn(b"\x07example\x03com\x00", message[-14:],
                      "the raw type-65 RDATA is written as given")

    def test_the_root_name_is_one_zero_byte(self) -> None:
        message = _build_dns_message(DNSMessage(questions=[DNSQuestion(".")]))
        self.assertEqual(message[12:13], b"\x00")


class TestItIsLossless(unittest.TestCase):

    def test_decode_of_the_encoding_is_the_message(self) -> None:
        decoded = parse_dns_udp(_build_dns_message(_response()))
        self.assertEqual(decoded, _response())

    def test_and_carries_no_raw(self) -> None:
        """A message packeteer compressed re-encodes from its fields."""
        decoded = parse_dns_udp(_build_dns_message(_response()))
        self.assertEqual(decoded.raw, b"")

    def test_over_tcp(self) -> None:
        wire = _build_dns_message_tcp(_response())
        self.assertEqual(struct.unpack_from("!H", wire)[0], len(wire) - 2)
        self.assertEqual(parse_dns_tcp(wire), _response())

    def test_case_is_matched_exactly(self) -> None:
        """A case-insensitive match would resolve to the target's spelling."""
        message = DNSMessage(
            questions=[DNSQuestion("Example.COM.")],
            answers=[_rr("example.com.", DNS_TYPE_A, DNSRDataA("1.2.3.4"))],
        )
        wire = _build_dns_message(message)
        self.assertEqual(_pointers(wire), [], "different case, no pointer")
        self.assertEqual(parse_dns_udp(wire), message)

    def test_conformance_holds(self) -> None:
        from packeteer import conformance

        proto = protocols.for_section("dns")
        assert proto is not None
        failures = conformance.check_protocol(proto, [_response()])
        self.assertEqual(failures, [], "\n".join(failures))


class TestThePointerLimit(unittest.TestCase):
    """A pointer holds 14 bits; past 0x3FFF names are written in full."""

    def _huge(self) -> DNSMessage:
        # 700 TXT records of ~30 bytes push the message past 16 KiB; the
        # answers after that repeat a name that first appeared before it.
        answers = [_rr("early.example.com.", DNS_TYPE_A, DNSRDataA("1.1.1.1"))]
        answers += [_rr(f"r{i}.pad.example.", DNS_TYPE_TXT, DNSRDataTXT([b"x" * 24]))
                    for i in range(700)]
        answers += [_rr("late.example.com.", DNS_TYPE_A, DNSRDataA("2.2.2.2")),
                    _rr("late.example.com.", DNS_TYPE_A, DNSRDataA("3.3.3.3"))]
        return DNSMessage(questions=[DNSQuestion("early.example.com.")], answers=answers)

    def test_no_pointer_targets_past_the_limit_and_it_still_parses(self) -> None:
        wire = _build_dns_message(self._huge())
        self.assertGreater(len(wire), 0x3FFF)
        for at in _pointers(wire):
            target = struct.unpack_from("!H", wire, at)[0] & 0x3FFF
            self.assertLessEqual(target, 0x3FFF)
        self.assertEqual(parse_dns_tcp(_build_dns_message_tcp(self._huge())), self._huge())

    def test_a_late_name_is_written_in_full(self) -> None:
        """A name first seen past the limit cannot be a target.

        `late.example.com` first appears past 0x3FFF, so its repeat cannot
        point at it — but `example.com` from the question still can be.
        """
        wire = _build_dns_message(self._huge())
        last = wire.rfind(b"\x04late")
        self.assertGreater(last, 0x3FFF)
        self.assertEqual(wire[last + 5:last + 7], b"\xc0\x12", "…then a pointer to example.com")


class TestTheSwitches(unittest.TestCase):

    def test_compress_false_reproduces_the_pre_0_14_0_bytes(self) -> None:
        full = _build_dns_message(_response(), compress=False)
        self.assertEqual(_pointers(full), [])
        self.assertEqual(parse_dns_udp(full).questions, _response().questions)

    def test_raw_wins_over_compress(self) -> None:
        message = _response()
        message.raw = b"\x00\x01" + b"\x00" * 10
        self.assertEqual(_build_dns_message(message), message.raw)
        self.assertEqual(_build_dns_message(message, compress=False), message.raw)

    def test_the_builder_takes_the_keyword(self) -> None:
        base = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
                .udp(src_port=53, dst_port=40000))
        compressed = base.dns(_response()).build()
        full = (PacketBuilder().ethernet().ip(src="10.0.0.1", dst="10.0.0.2")
                .udp(src_port=53, dst_port=40000).dns(_response(), compress=False).build())
        self.assertLess(len(compressed), len(full))
        self.assertEqual(parse_packet(compressed).dns, _response())
        self.assertEqual(parse_packet(full).dns.questions, _response().questions)

    def test_the_registry_path_compresses(self) -> None:
        """`.app()`, `build` and `stream` all go through `encode`."""
        proto = protocols.for_section("dns")
        assert proto is not None
        self.assertGreater(len(_pointers(proto.encode(_response(), "udp"))), 0)


if __name__ == "__main__":
    unittest.main()
