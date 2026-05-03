"""Tests for DNS encode/decode, sanitisation, and CLI integration."""
from __future__ import annotations

import argparse
import json
import struct
import unittest

from packeteer.generate.dns import (
    DNS_CLASS_IN,
    DNS_RCODE_NXDOMAIN,
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_MX,
    DNS_TYPE_NS,
    DNS_TYPE_PTR,
    DNS_TYPE_SOA,
    DNS_TYPE_TXT,
    MDNS_ADDR_IPV4,
    MDNS_PORT,
    DNSFlags,
    DNSMessage,
    DNSQuestion,
    DNSRDataA,
    DNSRDataAAAA,
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
    _encode_name,
)
from packeteer.parse.dns import parse_dns_tcp, parse_dns_udp


def _simple_query(name: str = "example.com.", qtype: int = DNS_TYPE_A) -> DNSMessage:
    return DNSMessage(
        id=0x1234,
        flags=DNSFlags(qr=False, rd=True),
        questions=[DNSQuestion(name=name, qtype=qtype, qclass=DNS_CLASS_IN)],
    )


def _rr(name: str, rtype: int, rdata: object, ttl: int = 300) -> DNSResourceRecord:
    return DNSResourceRecord(
        name=name, rtype=rtype, rclass=DNS_CLASS_IN, ttl=ttl, rdata=rdata,
    )


class TestEncodeName(unittest.TestCase):
    def test_simple(self) -> None:
        self.assertEqual(_encode_name("example.com"), b"\x07example\x03com\x00")

    def test_trailing_dot(self) -> None:
        self.assertEqual(_encode_name("example.com."), b"\x07example\x03com\x00")

    def test_root(self) -> None:
        self.assertEqual(_encode_name("."), b"\x00")

    def test_empty(self) -> None:
        self.assertEqual(_encode_name(""), b"\x00")


class TestEncodeDecodeRoundTrip(unittest.TestCase):
    def _rt(self, msg: DNSMessage) -> DNSMessage:
        wire = _build_dns_message(msg)
        return parse_dns_udp(wire)

    def test_query_roundtrip(self) -> None:
        msg = _simple_query()
        rt = self._rt(msg)
        self.assertEqual(rt.id, 0x1234)
        self.assertFalse(rt.flags.qr)
        self.assertTrue(rt.flags.rd)
        self.assertEqual(len(rt.questions), 1)
        self.assertEqual(rt.questions[0].name, "example.com.")
        self.assertEqual(rt.questions[0].qtype, DNS_TYPE_A)

    def test_response_with_a_record(self) -> None:
        msg = DNSMessage(
            id=0xABCD,
            flags=DNSFlags(qr=True, ra=True),
            questions=[DNSQuestion(name="host.example.com.")],
            answers=[_rr("host.example.com.", DNS_TYPE_A, DNSRDataA("1.2.3.4"))],
        )
        rt = self._rt(msg)
        self.assertTrue(rt.flags.qr)
        self.assertTrue(rt.flags.ra)
        self.assertEqual(len(rt.answers), 1)
        a = rt.answers[0].rdata
        self.assertIsInstance(a, DNSRDataA)
        assert isinstance(a, DNSRDataA)
        self.assertEqual(a.address, "1.2.3.4")

    def test_aaaa_record(self) -> None:
        msg = DNSMessage(
            id=1,
            answers=[_rr("v6.example.com.", DNS_TYPE_AAAA, DNSRDataAAAA("2001:db8::1"))],
        )
        rt = self._rt(msg)
        a = rt.answers[0].rdata
        self.assertIsInstance(a, DNSRDataAAAA)
        assert isinstance(a, DNSRDataAAAA)
        self.assertEqual(a.address, "2001:db8::1")

    def test_cname_record(self) -> None:
        msg = DNSMessage(
            id=2,
            answers=[_rr("www.example.com.", DNS_TYPE_CNAME, DNSRDataCNAME("host.example.com."))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataCNAME)
        assert isinstance(rdata, DNSRDataCNAME)
        self.assertEqual(rdata.name, "host.example.com.")

    def test_ns_record(self) -> None:
        msg = DNSMessage(
            id=3,
            answers=[_rr("example.com.", DNS_TYPE_NS, DNSRDataNS("ns1.example.com."))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataNS)
        assert isinstance(rdata, DNSRDataNS)
        self.assertEqual(rdata.name, "ns1.example.com.")

    def test_ptr_record(self) -> None:
        msg = DNSMessage(
            id=4,
            answers=[_rr("4.3.2.1.in-addr.arpa.", DNS_TYPE_PTR, DNSRDataPTR("host.example.com."))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataPTR)
        assert isinstance(rdata, DNSRDataPTR)
        self.assertEqual(rdata.name, "host.example.com.")

    def test_mx_record(self) -> None:
        msg = DNSMessage(
            id=5,
            answers=[_rr("example.com.", DNS_TYPE_MX, DNSRDataMX(10, "mail.example.com."))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataMX)
        assert isinstance(rdata, DNSRDataMX)
        self.assertEqual(rdata.preference, 10)
        self.assertEqual(rdata.exchange, "mail.example.com.")

    def test_soa_record(self) -> None:
        soa = DNSRDataSOA(
            mname="ns1.example.com.", rname="admin.example.com.",
            serial=2024010101, refresh=3600, retry=900, expire=604800, minimum=300,
        )
        msg = DNSMessage(id=6, authority=[_rr("example.com.", DNS_TYPE_SOA, soa)])
        rt = self._rt(msg)
        rdata = rt.authority[0].rdata
        self.assertIsInstance(rdata, DNSRDataSOA)
        assert isinstance(rdata, DNSRDataSOA)
        self.assertEqual(rdata.mname, "ns1.example.com.")
        self.assertEqual(rdata.rname, "admin.example.com.")
        self.assertEqual(rdata.serial, 2024010101)
        self.assertEqual(rdata.refresh, 3600)

    def test_txt_record(self) -> None:
        txt_data = [b"v=spf1 include:example.com ~all"]
        msg = DNSMessage(
            id=7,
            answers=[_rr("example.com.", DNS_TYPE_TXT, DNSRDataTXT(txt_data))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataTXT)
        assert isinstance(rdata, DNSRDataTXT)
        self.assertEqual(rdata.strings[0], b"v=spf1 include:example.com ~all")

    def test_multi_txt_strings(self) -> None:
        msg = DNSMessage(
            id=8,
            answers=[_rr("example.com.", DNS_TYPE_TXT, DNSRDataTXT([b"hello", b"world"]))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        assert isinstance(rdata, DNSRDataTXT)
        self.assertEqual(len(rdata.strings), 2)
        self.assertEqual(rdata.strings[1], b"world")

    def test_raw_rdata(self) -> None:
        msg = DNSMessage(
            id=9,
            answers=[_rr("example.com.", 99, DNSRDataRaw(rtype=99, data=b"\xde\xad\xbe\xef"))],
        )
        rt = self._rt(msg)
        rdata = rt.answers[0].rdata
        self.assertIsInstance(rdata, DNSRDataRaw)
        assert isinstance(rdata, DNSRDataRaw)
        self.assertEqual(rdata.data, b"\xde\xad\xbe\xef")

    def test_nxdomain_flags(self) -> None:
        msg = DNSMessage(
            id=10,
            flags=DNSFlags(qr=True, aa=True, rcode=DNS_RCODE_NXDOMAIN),
        )
        rt = self._rt(msg)
        self.assertTrue(rt.flags.aa)
        self.assertEqual(rt.flags.rcode, DNS_RCODE_NXDOMAIN)

    def test_multiple_questions(self) -> None:
        msg = DNSMessage(
            id=11,
            questions=[
                DNSQuestion("a.example.com.", DNS_TYPE_A),
                DNSQuestion("b.example.com.", DNS_TYPE_AAAA),
            ],
        )
        rt = self._rt(msg)
        self.assertEqual(len(rt.questions), 2)
        self.assertEqual(rt.questions[1].qtype, DNS_TYPE_AAAA)

    def test_all_sections_present(self) -> None:
        msg = DNSMessage(
            id=12,
            questions=[DNSQuestion("example.com.")],
            answers=[_rr("example.com.", DNS_TYPE_A, DNSRDataA("1.2.3.4"))],
            authority=[_rr("example.com.", DNS_TYPE_NS, DNSRDataNS("ns1.example.com."))],
            additional=[_rr("ns1.example.com.", DNS_TYPE_A, DNSRDataA("5.6.7.8"))],
        )
        rt = self._rt(msg)
        self.assertEqual(len(rt.answers), 1)
        self.assertEqual(len(rt.authority), 1)
        self.assertEqual(len(rt.additional), 1)


class TestTCPDNS(unittest.TestCase):
    def test_tcp_roundtrip(self) -> None:
        msg = _simple_query()
        wire = _build_dns_message_tcp(msg)
        length = struct.unpack_from("!H", wire, 0)[0]
        self.assertEqual(len(wire), 2 + length)
        rt = parse_dns_tcp(wire)
        self.assertEqual(rt.id, msg.id)
        self.assertEqual(rt.questions[0].name, "example.com.")

    def test_tcp_too_short(self) -> None:
        with self.assertRaises(ValueError):
            parse_dns_tcp(b"\x00")

    def test_tcp_truncated_payload(self) -> None:
        wire = struct.pack("!H", 100) + b"\x00" * 5
        with self.assertRaises(ValueError):
            parse_dns_tcp(wire)


class TestParserEdgeCases(unittest.TestCase):
    def test_too_short_header(self) -> None:
        with self.assertRaises(ValueError):
            parse_dns_udp(b"\x00" * 11)

    def test_pointer_loop_detection(self) -> None:
        # Craft a message with a pointer that loops back to itself
        header = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0)
        # Name: pointer to offset 12 (start of the name itself) → loop
        name_bytes = b"\xc0\x0c"  # pointer to offset 12
        qtype_class = struct.pack("!HH", DNS_TYPE_A, DNS_CLASS_IN)
        msg = header + name_bytes + qtype_class
        with self.assertRaises(ValueError):
            parse_dns_udp(msg)

    def test_compression_pointer_followed(self) -> None:
        # Build a response where the answer name uses a pointer to the question name
        name_wire = b"\x07example\x03com\x00"
        header = struct.pack("!HHHHHH", 1, 0x8000, 1, 1, 0, 0)
        question = name_wire + struct.pack("!HH", DNS_TYPE_A, DNS_CLASS_IN)
        q_offset = 12
        # Answer: pointer back to question name (offset 12)
        answer_name = struct.pack("!H", 0xC000 | q_offset)
        answer_rtype_class_ttl_rdlen = struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, 300, 4)
        answer_rdata = b"\x01\x02\x03\x04"
        wire = header + question + answer_name + answer_rtype_class_ttl_rdlen + answer_rdata
        msg = parse_dns_udp(wire)
        self.assertEqual(msg.answers[0].name, "example.com.")
        assert isinstance(msg.answers[0].rdata, DNSRDataA)
        self.assertEqual(msg.answers[0].rdata.address, "1.2.3.4")

    def test_malformed_a_rdata(self) -> None:
        # A record with wrong RDATA length falls back to DNSRDataRaw
        name_wire = b"\x07example\x03com\x00"
        header = struct.pack("!HHHHHH", 1, 0x8000, 0, 1, 0, 0)
        answer_name = name_wire
        answer_rtype_class_ttl_rdlen = struct.pack("!HHIH", DNS_TYPE_A, DNS_CLASS_IN, 300, 3)
        answer_rdata = b"\x01\x02\x03"
        wire = header + answer_name + answer_rtype_class_ttl_rdlen + answer_rdata
        msg = parse_dns_udp(wire)
        self.assertIsInstance(msg.answers[0].rdata, DNSRDataRaw)

    def test_malformed_aaaa_rdata(self) -> None:
        name_wire = b"\x07example\x03com\x00"
        header = struct.pack("!HHHHHH", 1, 0x8000, 0, 1, 0, 0)
        rtype_etc = struct.pack("!HHIH", DNS_TYPE_AAAA, DNS_CLASS_IN, 300, 4)
        wire = header + name_wire + rtype_etc + b"\x00" * 4
        msg = parse_dns_udp(wire)
        self.assertIsInstance(msg.answers[0].rdata, DNSRDataRaw)


class TestSanitiseDNS(unittest.TestCase):
    def _make_dns_packet_spec(self) -> dict:
        return {
            "packets": [
                {
                    "network": {"src": "1.2.3.4", "dst": "8.8.8.8", "protocol": "udp"},
                    "transport": {"src_port": 12345, "dst_port": 53},
                    "dns": {
                        "id": 0x1234,
                        "flags": {"qr": False, "opcode": 0, "aa": False, "tc": False,
                                  "rd": True, "ra": False, "rcode": 0},
                        "questions": [{"name": "mail.example.com.", "qtype": 1, "qclass": 1}],
                        "answers": [
                            {
                                "name": "mail.example.com.",
                                "rtype": DNS_TYPE_A,
                                "rclass": DNS_CLASS_IN,
                                "ttl": 300,
                                "rdata": {"address": "192.168.1.1"},
                            },
                            {
                                "name": "www.example.com.",
                                "rtype": DNS_TYPE_CNAME,
                                "rclass": DNS_CLASS_IN,
                                "ttl": 300,
                                "rdata": {"name": "host.example.com."},
                            },
                        ],
                        "authority": [
                            {
                                "name": "example.com.",
                                "rtype": DNS_TYPE_NS,
                                "rclass": DNS_CLASS_IN,
                                "ttl": 3600,
                                "rdata": {"name": "ns1.example.com."},
                            },
                        ],
                        "additional": [],
                    },
                }
            ]
        }

    def test_names_are_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        dns = result["packets"][0]["dns"]
        q_name = dns["questions"][0]["name"]
        self.assertNotIn("example", q_name)
        self.assertNotIn("mail", q_name)

    def test_label_consistency(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        dns = result["packets"][0]["dns"]
        # "mail.example.com." and "www.example.com." share "example" and "com" labels
        q_name = dns["questions"][0]["name"]
        ans_cname = dns["answers"][1]["name"]
        # Both names should end with the same two-label suffix (example→labelN, com→labelM)
        q_labels = q_name.rstrip(".").split(".")
        c_labels = ans_cname.rstrip(".").split(".")
        self.assertEqual(q_labels[-2:], c_labels[-2:])

    def test_a_rdata_address_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        dns = result["packets"][0]["dns"]
        addr = dns["answers"][0]["rdata"]["address"]
        self.assertNotEqual(addr, "192.168.1.1")

    def test_cname_rdata_name_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        dns = result["packets"][0]["dns"]
        cname = dns["answers"][1]["rdata"]["name"]
        self.assertNotIn("example", cname)

    def test_ns_rdata_name_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        dns = result["packets"][0]["dns"]
        ns_name = dns["authority"][0]["rdata"]["name"]
        self.assertNotIn("ns1", ns_name)

    def test_id_not_zeroed_by_default(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config)
        self.assertEqual(result["packets"][0]["dns"]["id"], 0x1234)

    def test_id_zeroed_with_dns_ids_option(self) -> None:
        from packeteer.sanitise import SanitiseOptions, sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config, SanitiseOptions(dns_ids=True))
        self.assertEqual(result["packets"][0]["dns"]["id"], 0)

    def test_mx_rdata_exchange_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = {
            "packets": [{
                "dns": {
                    "id": 1, "flags": {}, "questions": [],
                    "answers": [{
                        "name": "example.com.",
                        "rtype": DNS_TYPE_MX,
                        "rclass": 1, "ttl": 300,
                        "rdata": {"preference": 10, "exchange": "mail.example.com."},
                    }],
                    "authority": [], "additional": [],
                }
            }]
        }
        result = sanitise(config)
        exchange = result["packets"][0]["dns"]["answers"][0]["rdata"]["exchange"]
        self.assertNotIn("mail", exchange)

    def test_soa_mname_rname_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        config = {
            "packets": [{
                "dns": {
                    "id": 1, "flags": {}, "questions": [],
                    "answers": [],
                    "authority": [{
                        "name": "example.com.",
                        "rtype": DNS_TYPE_SOA,
                        "rclass": 1, "ttl": 3600,
                        "rdata": {
                            "mname": "ns1.example.com.", "rname": "admin.example.com.",
                            "serial": 1, "refresh": 3600, "retry": 900,
                            "expire": 604800, "minimum": 300,
                        },
                    }],
                    "additional": [],
                }
            }]
        }
        result = sanitise(config)
        rdata = result["packets"][0]["dns"]["authority"][0]["rdata"]
        self.assertNotIn("ns1", rdata["mname"])
        self.assertNotIn("admin", rdata["rname"])

    def test_no_ips_skips_a_rdata(self) -> None:
        from packeteer.sanitise import SanitiseOptions, sanitise
        config = self._make_dns_packet_spec()
        result = sanitise(config, SanitiseOptions(ips=False))
        addr = result["packets"][0]["dns"]["answers"][0]["rdata"]["address"]
        self.assertEqual(addr, "192.168.1.1")


class TestBuilderDNSMethod(unittest.TestCase):
    def test_builder_dns_udp(self) -> None:
        from packeteer.generate import PacketBuilder
        msg = _simple_query()
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="1.2.3.4", dst="8.8.8.8")
            .udp(src_port=12345, dst_port=53)
            .dns(msg)
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 40)

    def test_builder_dns_tcp(self) -> None:
        from packeteer.generate import PacketBuilder
        msg = _simple_query()
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="1.2.3.4", dst="8.8.8.8")
            .tcp(src_port=12345, dst_port=53)
            .dns(msg, tcp=True)
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 40)


class TestCLISanitiseDnsIds(unittest.TestCase):
    def test_dns_ids_flag_zeros_id(self) -> None:
        import os
        import tempfile

        from packeteer.__main__ import _cmd_sanitise
        config = {
            "packets": [{
                "dns": {
                    "id": 9999, "flags": {}, "questions": [],
                    "answers": [], "authority": [], "additional": [],
                }
            }]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(config, f)
            inp = f.name
        try:
            args = argparse.Namespace(
                input=inp, output=None, pcap=None, pcapng=None,
                no_ips=False, no_macs=False, ports=False,
                payload=False, timestamps=False, dns_ids=True,
            )
            import io
            from contextlib import redirect_stdout
            out = io.StringIO()
            with redirect_stdout(out):
                _cmd_sanitise(args)
            result = json.loads(out.getvalue())
            self.assertEqual(result["packets"][0]["dns"]["id"], 0)
        finally:
            os.unlink(inp)


class TestMDNS(unittest.TestCase):
    """mDNS-specific behaviour: QU bit, cache-flush bit, port 5353 dispatch."""

    # ── QU bit (unicast_response) ─────────────────────────────────────────────

    def test_qu_bit_roundtrip(self) -> None:
        msg = DNSMessage(
            id=0,
            flags=DNSFlags(qr=False, rd=False),
            questions=[DNSQuestion(
                "mydevice.local.", DNS_TYPE_A, DNS_CLASS_IN,
                unicast_response=True,
            )],
        )
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertTrue(rt.questions[0].unicast_response)
        self.assertEqual(rt.questions[0].qclass, DNS_CLASS_IN)

    def test_qu_bit_false_roundtrip(self) -> None:
        msg = DNSMessage(
            id=0,
            questions=[DNSQuestion("mydevice.local.", DNS_TYPE_A, DNS_CLASS_IN,
                                   unicast_response=False)],
        )
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertFalse(rt.questions[0].unicast_response)
        self.assertEqual(rt.questions[0].qclass, DNS_CLASS_IN)

    def test_qu_bit_does_not_corrupt_qclass(self) -> None:
        # Encoding with QU=True must not bleed into qclass value seen by caller.
        msg = DNSMessage(
            id=0,
            questions=[DNSQuestion("x.local.", DNS_TYPE_A, DNS_CLASS_IN,
                                   unicast_response=True)],
        )
        wire = _build_dns_message(msg)
        # Raw qclass on the wire should have top bit set.
        name_len = len(_encode_name("x.local."))
        raw_qclass = struct.unpack_from("!H", wire, 12 + name_len + 2)[0]
        self.assertTrue(raw_qclass & 0x8000)
        # Parsed qclass should be DNS_CLASS_IN (top bit stripped).
        rt = parse_dns_udp(wire)
        self.assertEqual(rt.questions[0].qclass, DNS_CLASS_IN)

    # ── Cache-flush bit ───────────────────────────────────────────────────────

    def test_cache_flush_roundtrip(self) -> None:
        rr = DNSResourceRecord(
            name="mydevice.local.", rtype=DNS_TYPE_A,
            rclass=DNS_CLASS_IN, ttl=120,
            rdata=DNSRDataA("192.168.1.99"),
            cache_flush=True,
        )
        msg = DNSMessage(id=0, answers=[rr])
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertTrue(rt.answers[0].cache_flush)
        self.assertEqual(rt.answers[0].rclass, DNS_CLASS_IN)

    def test_cache_flush_false_roundtrip(self) -> None:
        rr = DNSResourceRecord(
            name="mydevice.local.", rtype=DNS_TYPE_A,
            rclass=DNS_CLASS_IN, ttl=120,
            rdata=DNSRDataA("192.168.1.99"),
            cache_flush=False,
        )
        msg = DNSMessage(id=0, answers=[rr])
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertFalse(rt.answers[0].cache_flush)

    def test_cache_flush_does_not_corrupt_rclass(self) -> None:
        rr = DNSResourceRecord(
            name="x.local.", rtype=DNS_TYPE_A, rclass=DNS_CLASS_IN,
            ttl=120, rdata=DNSRDataA("1.2.3.4"), cache_flush=True,
        )
        msg = DNSMessage(id=0, answers=[rr])
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertEqual(rt.answers[0].rclass, DNS_CLASS_IN)

    def test_both_bits_independent(self) -> None:
        msg = DNSMessage(
            id=0,
            questions=[DNSQuestion("x.local.", unicast_response=True)],
            answers=[DNSResourceRecord(
                name="x.local.", rtype=DNS_TYPE_A, rclass=DNS_CLASS_IN,
                ttl=120, rdata=DNSRDataA("1.2.3.4"), cache_flush=True,
            )],
        )
        wire = _build_dns_message(msg)
        rt = parse_dns_udp(wire)
        self.assertTrue(rt.questions[0].unicast_response)
        self.assertTrue(rt.answers[0].cache_flush)

    # ── Port 5353 dispatch ────────────────────────────────────────────────────

    def test_parse_packet_dispatches_port_5353(self) -> None:
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        msg = DNSMessage(
            id=0,
            flags=DNSFlags(qr=False, rd=False),
            questions=[DNSQuestion("mydevice.local.", DNS_TYPE_A,
                                   unicast_response=True)],
        )
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="192.168.1.2", dst=MDNS_ADDR_IPV4)
            .udp(src_port=MDNS_PORT, dst_port=MDNS_PORT)
            .dns(msg)
            .build()
        )
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.dns)
        assert parsed.dns is not None
        self.assertTrue(parsed.dns.questions[0].unicast_response)

    def test_parse_packet_does_not_dispatch_other_port(self) -> None:
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="1.2.3.4", dst="5.6.7.8")
            .udp(src_port=12345, dst_port=9999)
            .payload(size=20)
            .build()
        )
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNone(parsed.dns)

    # ── Packet spec round-trip ────────────────────────────────────────────────

    def test_to_config_includes_unicast_response_when_true(self) -> None:
        from packeteer.parse import update_config
        msg = DNSMessage(
            id=0,
            questions=[DNSQuestion("mydevice.local.", DNS_TYPE_A,
                                   unicast_response=True)],
        )
        cfg: dict = {}
        update_config(cfg, msg)
        q = cfg["dns"]["questions"][0]
        self.assertTrue(q.get("unicast_response"))

    def test_to_config_omits_unicast_response_when_false(self) -> None:
        from packeteer.parse import update_config
        msg = DNSMessage(
            id=0,
            questions=[DNSQuestion("example.com.", DNS_TYPE_A,
                                   unicast_response=False)],
        )
        cfg: dict = {}
        update_config(cfg, msg)
        q = cfg["dns"]["questions"][0]
        self.assertNotIn("unicast_response", q)

    def test_to_config_includes_cache_flush_when_true(self) -> None:
        from packeteer.parse import update_config
        rr = DNSResourceRecord(
            name="mydevice.local.", rtype=DNS_TYPE_A, rclass=DNS_CLASS_IN,
            ttl=120, rdata=DNSRDataA("192.168.1.99"), cache_flush=True,
        )
        msg = DNSMessage(id=0, answers=[rr])
        cfg: dict = {}
        update_config(cfg, msg)
        ans = cfg["dns"]["answers"][0]
        self.assertTrue(ans.get("cache_flush"))

    def test_to_config_omits_cache_flush_when_false(self) -> None:
        from packeteer.parse import update_config
        rr = DNSResourceRecord(
            name="example.com.", rtype=DNS_TYPE_A, rclass=DNS_CLASS_IN,
            ttl=300, rdata=DNSRDataA("1.2.3.4"), cache_flush=False,
        )
        msg = DNSMessage(id=0, answers=[rr])
        cfg: dict = {}
        update_config(cfg, msg)
        ans = cfg["dns"]["answers"][0]
        self.assertNotIn("cache_flush", ans)

    # ── Constants ─────────────────────────────────────────────────────────────

    def test_mdns_constants_exported(self) -> None:
        from packeteer.generate import MDNS_ADDR_IPV4, MDNS_ADDR_IPV6, MDNS_PORT
        self.assertEqual(MDNS_PORT, 5353)
        self.assertEqual(MDNS_ADDR_IPV4, "224.0.0.251")
        self.assertEqual(MDNS_ADDR_IPV6, "ff02::fb")


if __name__ == "__main__":
    unittest.main()
