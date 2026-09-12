"""Whether a link type is supported is a question a caller can ask (#138).

Before this the only signal was `UnsupportedLinkTypeWarning`, which fires once
per file under the default filter and so answers "did this file have one"
rather than the per-packet or the up-front question.  zpfwire inferred it
from which header objects were `None`, which misfiled a raw-IP capture with a
bad IP header as a link-layer problem.
"""
from __future__ import annotations

import io
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path

from packeteer.generate import PacketBuilder
from packeteer.parse import (
    SUPPORTED_LINK_TYPES,
    UnsupportedLinkTypeWarning,
    parse_packet,
    pcap_info,
    supports_link_type,
)
from packeteer.parse.info import _choose_link_type, format_pcap_info
from packeteer.pcap import (
    LINKTYPE_ETHERNET,
    LINKTYPE_LINUX_SLL,
    LINKTYPE_LINUX_SLL2,
    LINKTYPE_LOOP,
    LINKTYPE_NULL,
    LINKTYPE_RAW,
    write_pcap,
)

_IEEE802_15_4 = 191          # a real link type packeteer has no reader for
_USER0 = 147


def _ip_frame() -> bytes:
    return (PacketBuilder().ip(src="192.0.2.1", dst="192.0.2.9")
            .udp(dst_port=9).payload(data=b"x").build())


def _frame_for(link_type: int) -> bytes:
    """Build a minimal frame carrying an IPv4 datagram under *link_type*'s header."""
    inner = _ip_frame()
    if link_type == LINKTYPE_ETHERNET:
        return (PacketBuilder().ethernet().ip(src="192.0.2.1", dst="192.0.2.9")
                .udp(dst_port=9).payload(data=b"x").build())
    if link_type == LINKTYPE_RAW:
        return inner
    if link_type == LINKTYPE_LINUX_SLL:
        return (PacketBuilder().sll().ip(src="192.0.2.1", dst="192.0.2.9")
                .udp(dst_port=9).payload(data=b"x").build())
    if link_type == LINKTYPE_LINUX_SLL2:
        return (PacketBuilder().sll2().ip(src="192.0.2.1", dst="192.0.2.9")
                .udp(dst_port=9).payload(data=b"x").build())
    if link_type == LINKTYPE_NULL:
        return struct.pack("<I", 2) + inner          # AF_INET, host order
    if link_type == LINKTYPE_LOOP:
        return struct.pack(">I", 2) + inner          # AF_INET, network order
    raise AssertionError(f"no fixture for link type {link_type}")


def _parse_warns(frame: bytes, link_type: int) -> int:
    """Return how many UnsupportedLinkTypeWarnings parsing *frame* raises."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        parse_packet(frame, link_type=link_type)
    return len([w for w in caught if issubclass(w.category, UnsupportedLinkTypeWarning)])


class TestTheSetIsTheDefinition(unittest.TestCase):
    """Membership and the parser agree in both directions."""

    def test_every_member_decodes_without_warning(self) -> None:
        for link_type in sorted(SUPPORTED_LINK_TYPES):
            with self.subTest(link_type=link_type):
                frame = _frame_for(link_type)
                self.assertEqual(_parse_warns(frame, link_type), 0)
                pkt = parse_packet(frame, link_type=link_type)
                self.assertIsNotNone(pkt.ip, "the fixture reaches the IP layer")

    def test_a_non_member_warns_and_decodes_nothing(self) -> None:
        for link_type in (_IEEE802_15_4, _USER0, 0x7FFF):
            with self.subTest(link_type=link_type):
                self.assertNotIn(link_type, SUPPORTED_LINK_TYPES)
                frame = _frame_for(LINKTYPE_ETHERNET)
                self.assertEqual(_parse_warns(frame, link_type), 1)
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    pkt = parse_packet(frame, link_type=link_type)
                self.assertIsNone(pkt.ethernet)
                self.assertIsNone(pkt.ip)
                self.assertEqual(pkt.payload, frame)

    def test_the_predicate_is_membership(self) -> None:
        for link_type in range(0, 300):
            self.assertEqual(supports_link_type(link_type),
                             link_type in SUPPORTED_LINK_TYPES, link_type)

    def test_what_is_supported_today(self) -> None:
        """Adding one is deliberate; this names what is here today."""
        self.assertEqual(SUPPORTED_LINK_TYPES, {
            LINKTYPE_NULL, LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LOOP,
            LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2,
        })

    def test_auto_detection_only_tries_supported_types(self) -> None:
        """A candidate the parser cannot decode could never score, but say so."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            chosen = _choose_link_type([(_ip_frame(), 0, 0)], declared=_USER0)
        self.assertIn(chosen, SUPPORTED_LINK_TYPES)


class TestTheAnswerIsOnTheReport(unittest.TestCase):
    """`pcap_info` says it before a packet is read, which is when it is useful."""

    def _capture(self, link_type: int) -> str:
        directory = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, directory, True)
        path = str(Path(directory) / "capture.pcap")
        write_pcap([(_frame_for(LINKTYPE_ETHERNET), 1, 0)] * 3,
                   path=path, link_type=link_type)
        return path

    def test_supported(self) -> None:
        info = pcap_info(path=self._capture(LINKTYPE_ETHERNET))
        self.assertTrue(info.link_type_supported)
        self.assertTrue(info.to_dict()["link_type_supported"])
        self.assertNotIn("not supported", format_pcap_info(info))

    def test_unsupported(self) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            info = pcap_info(path=self._capture(_IEEE802_15_4), auto_link_type=False)
        self.assertFalse(info.link_type_supported)
        self.assertFalse(info.to_dict()["link_type_supported"])
        report = format_pcap_info(info)
        self.assertIn("not supported", report)
        self.assertIn(f"link type {_IEEE802_15_4} is not one packeteer can decode", report)
        self.assertNotIn("may be malformed", report,
                         "the cause is known, so the symptom is not offered")

    def test_it_follows_the_type_used_not_the_one_declared(self) -> None:
        """An override to a supported type makes the capture readable."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            info = pcap_info(path=self._capture(_IEEE802_15_4),
                             link_type=LINKTYPE_ETHERNET)
        self.assertTrue(info.link_type_supported)
        self.assertEqual(info.declared_link_type, _IEEE802_15_4)

    def test_the_cli_says_so(self) -> None:
        done = subprocess.run(
            [sys.executable, "-m", "packeteer", "file-info", "--no-auto-link-type",
             self._capture(_IEEE802_15_4)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("not supported", done.stdout)

    def test_the_loopback_types_have_names_on_the_report(self) -> None:
        buf = io.BytesIO()
        write_pcap([(_frame_for(LINKTYPE_LOOP), 1, 0)], file_object=buf,
                   link_type=LINKTYPE_LOOP)
        buf.seek(0)
        info = pcap_info(file_object=buf, auto_link_type=False)
        self.assertIn("loop (108)", format_pcap_info(info))


if __name__ == "__main__":
    unittest.main()
