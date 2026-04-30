"""Tests for DHCP encode/decode, sanitisation, builder, and CLI integration."""
from __future__ import annotations

import argparse
import json
import struct
import unittest

from packeteer.generate.dhcp import (
    DHCP_MAGIC_COOKIE,
    DHCP_MSG_ACK,
    DHCP_MSG_DISCOVER,
    DHCP_MSG_OFFER,
    DHCP_MSG_REQUEST,
    DHCP_OP_REPLY,
    DHCP_OP_REQUEST,
    DHCP_OPT_DNS_SERVER,
    DHCP_OPT_DOMAIN_NAME,
    DHCP_OPT_MESSAGE_TYPE,
    DHCP_OPT_ROUTER,
    DHCP_OPT_SERVER_ID,
    DHCP_OPT_SUBNET_MASK,
    DHCP_PORT_CLIENT,
    DHCP_PORT_SERVER,
    DHCPMessage,
    DHCPOptClientID,
    DHCPOptDNSServer,
    DHCPOptDomainName,
    DHCPOptHostname,
    DHCPOptLeaseTime,
    DHCPOptMessageType,
    DHCPOptParamRequestList,
    DHCPOptRaw,
    DHCPOptRequestedIP,
    DHCPOptRouter,
    DHCPOptServerID,
    DHCPOptSubnetMask,
    DHCPOptVendorClassID,
    _build_dhcp_message,
)
from packeteer.parse.dhcp import parse_dhcp

_CLIENT_MAC = bytes.fromhex("aabbccddeeff") + b"\x00" * 10


def _discover() -> DHCPMessage:
    return DHCPMessage(
        op=DHCP_OP_REQUEST,
        xid=0x12345678,
        chaddr=_CLIENT_MAC,
        options=[
            DHCPOptMessageType(DHCP_MSG_DISCOVER),
            DHCPOptParamRequestList(codes=[
                DHCP_OPT_SUBNET_MASK, DHCP_OPT_ROUTER,
                DHCP_OPT_DNS_SERVER, DHCP_OPT_DOMAIN_NAME,
            ]),
        ],
    )


def _offer() -> DHCPMessage:
    return DHCPMessage(
        op=DHCP_OP_REPLY,
        xid=0x12345678,
        yiaddr="192.168.1.100",
        siaddr="192.168.1.1",
        chaddr=_CLIENT_MAC,
        options=[
            DHCPOptMessageType(DHCP_MSG_OFFER),
            DHCPOptSubnetMask("255.255.255.0"),
            DHCPOptRouter(["192.168.1.1"]),
            DHCPOptDNSServer(["8.8.8.8", "8.8.4.4"]),
            DHCPOptLeaseTime(86400),
            DHCPOptServerID("192.168.1.1"),
        ],
    )


class TestDHCPEncode(unittest.TestCase):
    def test_wire_length(self) -> None:
        wire = _build_dhcp_message(_discover())
        # 236 fixed + 4 cookie + options + END
        self.assertGreaterEqual(len(wire), 241)

    def test_magic_cookie_present(self) -> None:
        wire = _build_dhcp_message(_discover())
        self.assertEqual(wire[236:240], DHCP_MAGIC_COOKIE)

    def test_fixed_header_fields(self) -> None:
        msg = DHCPMessage(
            op=DHCP_OP_REPLY,
            xid=0xDEADBEEF,
            yiaddr="10.0.0.5",
            chaddr=b"\x00" * 16,
        )
        wire = _build_dhcp_message(msg)
        op, htype, hlen, hops = struct.unpack_from("!BBBB", wire, 0)
        (xid,) = struct.unpack_from("!I", wire, 4)
        yiaddr = wire[16:20]
        self.assertEqual(op, DHCP_OP_REPLY)
        self.assertEqual(xid, 0xDEADBEEF)
        import socket
        self.assertEqual(socket.inet_ntoa(yiaddr), "10.0.0.5")

    def test_end_option_appended(self) -> None:
        wire = _build_dhcp_message(DHCPMessage(chaddr=b"\x00" * 16))
        self.assertEqual(wire[-1], 255)

    def test_chaddr_wrong_length_raises(self) -> None:
        with self.assertRaises(ValueError):
            _build_dhcp_message(DHCPMessage(chaddr=b"\x00" * 6))

    def test_message_type_option_encoded(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptMessageType(DHCP_MSG_DISCOVER)],
        )
        wire = _build_dhcp_message(msg)
        opts = wire[240:]
        self.assertIn(bytes([DHCP_OPT_MESSAGE_TYPE, 1, DHCP_MSG_DISCOVER]), opts)

    def test_subnet_mask_option_encoded(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptSubnetMask("255.255.0.0")],
        )
        wire = _build_dhcp_message(msg)
        opts = wire[240:]
        import socket
        expected = bytes([DHCP_OPT_SUBNET_MASK, 4]) + socket.inet_aton("255.255.0.0")
        self.assertIn(expected, opts)

    def test_raw_option_passthrough(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRaw(code=77, data=b"\xde\xad")],
        )
        wire = _build_dhcp_message(msg)
        opts = wire[240:]
        self.assertIn(b"\x4d\x02\xde\xad", opts)  # 77, len=2, data


class TestDHCPDecodeRoundTrip(unittest.TestCase):
    def _rt(self, msg: DHCPMessage) -> DHCPMessage:
        return parse_dhcp(_build_dhcp_message(msg))

    def test_discover_roundtrip(self) -> None:
        rt = self._rt(_discover())
        self.assertEqual(rt.op, DHCP_OP_REQUEST)
        self.assertEqual(rt.xid, 0x12345678)
        self.assertEqual(rt.chaddr, _CLIENT_MAC)
        self.assertIsInstance(rt.options[0], DHCPOptMessageType)
        assert isinstance(rt.options[0], DHCPOptMessageType)
        self.assertEqual(rt.options[0].mtype, DHCP_MSG_DISCOVER)

    def test_offer_roundtrip(self) -> None:
        rt = self._rt(_offer())
        self.assertEqual(rt.op, DHCP_OP_REPLY)
        self.assertEqual(rt.yiaddr, "192.168.1.100")
        msg_type = next(o for o in rt.options if isinstance(o, DHCPOptMessageType))
        self.assertEqual(msg_type.mtype, DHCP_MSG_OFFER)
        server_id = next(o for o in rt.options if isinstance(o, DHCPOptServerID))
        self.assertEqual(server_id.address, "192.168.1.1")

    def test_subnet_mask_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptSubnetMask("255.255.255.0")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptSubnetMask)
        assert isinstance(opt, DHCPOptSubnetMask)
        self.assertEqual(opt.mask, "255.255.255.0")

    def test_router_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRouter(["10.0.0.1", "10.0.0.2"])],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptRouter)
        assert isinstance(opt, DHCPOptRouter)
        self.assertEqual(opt.routers, ["10.0.0.1", "10.0.0.2"])

    def test_dns_server_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptDNSServer(["1.1.1.1"])],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptDNSServer)
        assert isinstance(opt, DHCPOptDNSServer)
        self.assertEqual(opt.servers, ["1.1.1.1"])

    def test_hostname_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptHostname("myhost")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptHostname)
        assert isinstance(opt, DHCPOptHostname)
        self.assertEqual(opt.hostname, "myhost")

    def test_domain_name_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptDomainName("example.com")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptDomainName)
        assert isinstance(opt, DHCPOptDomainName)
        self.assertEqual(opt.domain, "example.com")

    def test_requested_ip_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRequestedIP("192.168.1.50")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptRequestedIP)
        assert isinstance(opt, DHCPOptRequestedIP)
        self.assertEqual(opt.address, "192.168.1.50")

    def test_lease_time_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptLeaseTime(3600)],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptLeaseTime)
        assert isinstance(opt, DHCPOptLeaseTime)
        self.assertEqual(opt.seconds, 3600)

    def test_param_request_list_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptParamRequestList([1, 3, 6, 15])],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptParamRequestList)
        assert isinstance(opt, DHCPOptParamRequestList)
        self.assertEqual(opt.codes, [1, 3, 6, 15])

    def test_vendor_class_id_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptVendorClassID(b"MSFT 5.0")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptVendorClassID)
        assert isinstance(opt, DHCPOptVendorClassID)
        self.assertEqual(opt.data, b"MSFT 5.0")

    def test_client_id_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptClientID(b"\x01\xaa\xbb\xcc\xdd\xee\xff")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptClientID)
        assert isinstance(opt, DHCPOptClientID)
        self.assertEqual(opt.data, b"\x01\xaa\xbb\xcc\xdd\xee\xff")

    def test_raw_option_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRaw(code=77, data=b"\x01\x02\x03")],
        )
        rt = self._rt(msg)
        opt = rt.options[0]
        self.assertIsInstance(opt, DHCPOptRaw)
        assert isinstance(opt, DHCPOptRaw)
        self.assertEqual(opt.code, 77)
        self.assertEqual(opt.data, b"\x01\x02\x03")

    def test_sname_and_file_roundtrip(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            sname=b"bootserver\x00" + b"\x00" * 53,
            file=b"pxelinux.0\x00" + b"\x00" * 117,
        )
        rt = self._rt(msg)
        self.assertTrue(rt.sname.startswith(b"bootserver"))
        self.assertTrue(rt.file.startswith(b"pxelinux.0"))

    def test_multiple_options_order_preserved(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[
                DHCPOptMessageType(DHCP_MSG_ACK),
                DHCPOptLeaseTime(7200),
                DHCPOptSubnetMask("255.255.255.0"),
            ],
        )
        rt = self._rt(msg)
        self.assertIsInstance(rt.options[0], DHCPOptMessageType)
        self.assertIsInstance(rt.options[1], DHCPOptLeaseTime)
        self.assertIsInstance(rt.options[2], DHCPOptSubnetMask)

    def test_all_ip_fields_roundtrip(self) -> None:
        msg = DHCPMessage(
            op=DHCP_OP_REPLY,
            xid=0xABCD,
            ciaddr="10.0.0.1",
            yiaddr="10.0.0.50",
            siaddr="10.0.0.254",
            giaddr="10.0.1.1",
            chaddr=b"\x00" * 16,
        )
        rt = self._rt(msg)
        self.assertEqual(rt.ciaddr, "10.0.0.1")
        self.assertEqual(rt.yiaddr, "10.0.0.50")
        self.assertEqual(rt.siaddr, "10.0.0.254")
        self.assertEqual(rt.giaddr, "10.0.1.1")


class TestDHCPParserEdgeCases(unittest.TestCase):
    def test_too_short_raises(self) -> None:
        with self.assertRaises(ValueError):
            parse_dhcp(b"\x00" * 240)

    def test_bad_magic_cookie_raises(self) -> None:
        wire = _build_dhcp_message(DHCPMessage(chaddr=b"\x00" * 16))
        # corrupt magic cookie
        corrupted = wire[:236] + b"\x00\x00\x00\x00" + wire[240:]
        with self.assertRaises(ValueError):
            parse_dhcp(corrupted)

    def test_unknown_option_becomes_raw(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRaw(code=200, data=b"\xff\xfe")],
        )
        rt = parse_dhcp(_build_dhcp_message(msg))
        self.assertIsInstance(rt.options[0], DHCPOptRaw)
        assert isinstance(rt.options[0], DHCPOptRaw)
        self.assertEqual(rt.options[0].code, 200)

    def test_end_option_stops_parsing(self) -> None:
        # Insert END (255) manually then extra garbage — should be ignored.
        base = _build_dhcp_message(DHCPMessage(chaddr=b"\x00" * 16))
        # strip the END, inject code + END + garbage
        without_end = base[:-1]
        with_garbage = without_end + bytes([DHCP_OPT_MESSAGE_TYPE, 1, 99, 255, 12, 1, 99])
        rt = parse_dhcp(with_garbage)
        types = [type(o) for o in rt.options]
        self.assertIn(DHCPOptMessageType, types)
        # The extra opt after END must not appear
        self.assertEqual(len([o for o in rt.options if isinstance(o, DHCPOptMessageType)]), 1)

    def test_pad_option_skipped(self) -> None:
        # Build wire manually with PAD (0) bytes before a real option.
        base = _build_dhcp_message(DHCPMessage(chaddr=b"\x00" * 16))
        without_end = base[:-1]
        extra = bytes([DHCP_OPT_MESSAGE_TYPE, 1, DHCP_MSG_REQUEST, 255])
        padded = without_end + b"\x00\x00\x00" + extra
        rt = parse_dhcp(padded)
        msg_opts = [o for o in rt.options if isinstance(o, DHCPOptMessageType)]
        self.assertEqual(len(msg_opts), 1)
        self.assertEqual(msg_opts[0].mtype, DHCP_MSG_REQUEST)


class TestBuilderDHCPMethod(unittest.TestCase):
    def test_builder_discover(self) -> None:
        from packeteer.generate import PacketBuilder
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="0.0.0.0", dst="255.255.255.255")
            .udp(src_port=DHCP_PORT_CLIENT, dst_port=DHCP_PORT_SERVER)
            .dhcp(_discover())
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 280)

    def test_builder_offer(self) -> None:
        from packeteer.generate import PacketBuilder
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="192.168.1.1", dst="255.255.255.255")
            .udp(src_port=DHCP_PORT_SERVER, dst_port=DHCP_PORT_CLIENT)
            .dhcp(_offer())
            .build()
        )
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 280)

    def test_builder_dhcp_payload_parseable(self) -> None:
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="0.0.0.0", dst="255.255.255.255")
            .udp(src_port=DHCP_PORT_CLIENT, dst_port=DHCP_PORT_SERVER)
            .dhcp(_discover())
            .build()
        )
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.dhcp)
        assert parsed.dhcp is not None
        self.assertEqual(parsed.dhcp.xid, 0x12345678)


class TestParsePacketDHCPDispatch(unittest.TestCase):
    def _pkt(self, src_port: int, dst_port: int) -> bytes:
        from packeteer.generate import PacketBuilder
        return (
            PacketBuilder()
            .ethernet()
            .ip(src="0.0.0.0", dst="255.255.255.255")
            .udp(src_port=src_port, dst_port=dst_port)
            .dhcp(_discover())
            .build()
        )

    def test_dispatch_on_port_67(self) -> None:
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        pkt = self._pkt(DHCP_PORT_CLIENT, DHCP_PORT_SERVER)
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.dhcp)

    def test_dispatch_on_port_68(self) -> None:
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        pkt = self._pkt(DHCP_PORT_SERVER, DHCP_PORT_CLIENT)
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNotNone(parsed.dhcp)

    def test_no_dispatch_on_other_port(self) -> None:
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
        self.assertIsNone(parsed.dhcp)

    def test_dhcp_not_parsed_over_tcp(self) -> None:
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet
        from packeteer.pcap import LINKTYPE_ETHERNET
        # DHCP over TCP port 67 — should NOT parse as DHCP (TCP only)
        pkt = (
            PacketBuilder()
            .ethernet()
            .ip(src="1.2.3.4", dst="5.6.7.8")
            .tcp(src_port=12345, dst_port=DHCP_PORT_SERVER)
            .payload(size=20)
            .build()
        )
        parsed = parse_packet(pkt, link_type=LINKTYPE_ETHERNET)
        self.assertIsNone(parsed.dhcp)


class TestToConfigDHCP(unittest.TestCase):
    def _cfg(self, msg: DHCPMessage) -> dict:
        from packeteer.parse import update_config
        cfg: dict = {}
        update_config(cfg, msg)
        return cfg["dhcp"]

    def test_fixed_fields_serialised(self) -> None:
        dhcp = self._cfg(_offer())
        self.assertEqual(dhcp["op"], DHCP_OP_REPLY)
        self.assertEqual(dhcp["xid"], 0x12345678)
        self.assertEqual(dhcp["yiaddr"], "192.168.1.100")

    def test_options_serialised(self) -> None:
        dhcp = self._cfg(_offer())
        codes = [o["code"] for o in dhcp["options"]]
        self.assertIn(DHCP_OPT_MESSAGE_TYPE, codes)
        self.assertIn(DHCP_OPT_SUBNET_MASK, codes)
        self.assertIn(DHCP_OPT_ROUTER, codes)

    def test_chaddr_serialised_as_hex(self) -> None:
        dhcp = self._cfg(_discover())
        self.assertEqual(dhcp["chaddr"][:12], "aabbccddeeff")

    def test_raw_option_serialised(self) -> None:
        msg = DHCPMessage(
            chaddr=b"\x00" * 16,
            options=[DHCPOptRaw(code=200, data=b"\xab\xcd")],
        )
        dhcp = self._cfg(msg)
        self.assertEqual(dhcp["options"][0], {"code": 200, "data": "abcd"})


class TestSanitiseDHCP(unittest.TestCase):
    def _spec(self, extra_opts: list | None = None) -> dict:
        opts = [
            {"code": DHCP_OPT_MESSAGE_TYPE, "mtype": DHCP_MSG_OFFER},
            {"code": DHCP_OPT_SUBNET_MASK, "mask": "255.255.255.0"},
            {"code": DHCP_OPT_ROUTER, "routers": ["192.168.1.1"]},
            {"code": DHCP_OPT_DNS_SERVER, "servers": ["8.8.8.8"]},
            {"code": DHCP_OPT_SERVER_ID, "address": "192.168.1.1"},
        ]
        if extra_opts:
            opts.extend(extra_opts)
        return {
            "packets": [{
                "dhcp": {
                    "op": 2, "htype": 1, "hlen": 6, "hops": 0,
                    "xid": 0xDEADBEEF,
                    "secs": 0, "flags": 0,
                    "ciaddr": "0.0.0.0",
                    "yiaddr": "192.168.1.100",
                    "siaddr": "192.168.1.1",
                    "giaddr": "0.0.0.0",
                    "chaddr": "aabbccddeeff" + "00" * 10,
                    "sname": "", "file": "",
                    "options": opts,
                }
            }]
        }

    def test_yiaddr_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        self.assertNotEqual(result["packets"][0]["dhcp"]["yiaddr"], "192.168.1.100")

    def test_siaddr_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        self.assertNotEqual(result["packets"][0]["dhcp"]["siaddr"], "192.168.1.1")

    def test_zero_addr_not_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        self.assertEqual(result["packets"][0]["dhcp"]["ciaddr"], "0.0.0.0")
        self.assertEqual(result["packets"][0]["dhcp"]["giaddr"], "0.0.0.0")

    def test_chaddr_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        self.assertNotEqual(result["packets"][0]["dhcp"]["chaddr"][:12], "aabbccddeeff")

    def test_chaddr_not_replaced_with_macs_false(self) -> None:
        from packeteer.sanitise import SanitiseOptions, sanitise
        result = sanitise(self._spec(), SanitiseOptions(macs=False))
        self.assertEqual(result["packets"][0]["dhcp"]["chaddr"][:12], "aabbccddeeff")

    def test_router_option_ip_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        router_opt = next(
            o for o in result["packets"][0]["dhcp"]["options"]
            if o["code"] == DHCP_OPT_ROUTER
        )
        self.assertNotEqual(router_opt["routers"][0], "192.168.1.1")

    def test_dns_server_option_ip_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        dns_opt = next(
            o for o in result["packets"][0]["dhcp"]["options"]
            if o["code"] == DHCP_OPT_DNS_SERVER
        )
        self.assertNotEqual(dns_opt["servers"][0], "8.8.8.8")

    def test_server_id_option_ip_replaced(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        srv_opt = next(
            o for o in result["packets"][0]["dhcp"]["options"]
            if o["code"] == DHCP_OPT_SERVER_ID
        )
        self.assertNotEqual(srv_opt["address"], "192.168.1.1")

    def test_xid_preserved_by_default(self) -> None:
        from packeteer.sanitise import sanitise
        result = sanitise(self._spec())
        self.assertEqual(result["packets"][0]["dhcp"]["xid"], 0xDEADBEEF)

    def test_xid_zeroed_with_dhcp_xids_option(self) -> None:
        from packeteer.sanitise import SanitiseOptions, sanitise
        result = sanitise(self._spec(), SanitiseOptions(dhcp_xids=True))
        self.assertEqual(result["packets"][0]["dhcp"]["xid"], 0)

    def test_original_not_mutated(self) -> None:
        from packeteer.sanitise import sanitise
        config = self._spec()
        sanitise(config)
        self.assertEqual(config["packets"][0]["dhcp"]["yiaddr"], "192.168.1.100")

    def test_ip_consistency_across_options(self) -> None:
        from packeteer.sanitise import sanitise
        # siaddr and server-id option should map the same source IP to same synthetic value
        result = sanitise(self._spec())
        d = result["packets"][0]["dhcp"]
        srv_opt = next(
            o for o in d["options"] if o["code"] == DHCP_OPT_SERVER_ID
        )
        self.assertEqual(d["siaddr"], srv_opt["address"])

    def test_no_ips_skips_option_ips(self) -> None:
        from packeteer.sanitise import SanitiseOptions, sanitise
        result = sanitise(self._spec(), SanitiseOptions(ips=False))
        router_opt = next(
            o for o in result["packets"][0]["dhcp"]["options"]
            if o["code"] == DHCP_OPT_ROUTER
        )
        self.assertEqual(router_opt["routers"][0], "192.168.1.1")


class TestCLIDHCPXids(unittest.TestCase):
    def test_dhcp_xids_flag_zeros_xid(self) -> None:
        import os
        import tempfile

        from packeteer.__main__ import _cmd_sanitise
        config = {
            "packets": [{
                "dhcp": {
                    "op": 1, "htype": 1, "hlen": 6, "hops": 0,
                    "xid": 0x12345678,
                    "secs": 0, "flags": 0,
                    "ciaddr": "0.0.0.0", "yiaddr": "0.0.0.0",
                    "siaddr": "0.0.0.0", "giaddr": "0.0.0.0",
                    "chaddr": "00" * 16,
                    "sname": "", "file": "", "options": [],
                }
            }]
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config, f)
            inp = f.name
        try:
            args = argparse.Namespace(
                input=inp, output=None, pcap=None, pcapng=None,
                no_ips=False, no_macs=False, ports=False,
                payload=False, timestamps=False,
                dns_ids=False, dhcp_xids=True,
            )
            import io
            from contextlib import redirect_stdout
            out = io.StringIO()
            with redirect_stdout(out):
                _cmd_sanitise(args)
            result = json.loads(out.getvalue())
            self.assertEqual(result["packets"][0]["dhcp"]["xid"], 0)
        finally:
            os.unlink(inp)


if __name__ == "__main__":
    unittest.main()
