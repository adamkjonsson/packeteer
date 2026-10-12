"""Corruption flips the payload's last byte, never the frame's padding (#200).

Both corruption passes flipped ``raw[-1]``, the frame's last byte.  An
Ethernet frame under 60 bytes is padded, so there the flip landed in the
padding, outside the IP length and every checksum: the packet was labelled
``CORRUPT[i]`` and was a valid packet with its payload unchanged.  The flip
now lands on the last byte of the IP datagram, found from the IP header.
"""
from __future__ import annotations

import ipaddress
import random
import unittest

from packeteer.generate.checksum import ones_complement_checksum
from packeteer.generate.impairments import ImpairmentConfig, apply_datagram_impairments
from packeteer.generate.payloads.vpn import VPNConfig, generate_vpn_stream
from packeteer.generate.stream_encap import ESPEncap, VLANEncap
from packeteer.generate.tcp_stream import TCPStreamConfig, generate_tcp_stream
from packeteer.generate.udp_stream import UDPStreamConfig, generate_udp_stream

#: Either side of every padding threshold: IPv4 UDP pads under 18 bytes of
#: payload, IPv4 TCP without options under 6, IPv6 under 6.
_SIZES = (1, 2, 5, 6, 7, 10, 17, 18, 19, 30)

_FAMILIES = {
    "IPv4": ("10.0.0.2", "10.0.0.1"),
    "IPv6": ("2001:db8::2", "2001:db8::1"),
}

_PROTO = {"udp": 17, "tcp": 6}


def _layout(raw: bytes, ip_start: int) -> tuple[bytes, int, int, int]:
    """Return the pseudo-header, the segment's start and end, and the IP protocol."""
    ip = raw[ip_start:]
    if ip[0] >> 4 == 4:
        header_len = (ip[0] & 0x0F) * 4
        end = ip_start + int.from_bytes(ip[2:4], "big")
        proto = ip[9]
        length = end - ip_start - header_len
        pseudo = ip[12:20] + bytes([0, proto]) + length.to_bytes(2, "big")
    else:
        header_len = 40
        end = ip_start + 40 + int.from_bytes(ip[4:6], "big")
        proto = ip[6]
        length = end - ip_start - header_len
        pseudo = ip[8:40] + length.to_bytes(4, "big") + bytes([0, 0, 0, proto])
    return pseudo, ip_start + header_len, end, proto


def _checksum_ok(raw: bytes, ip_start: int = 14) -> bool:
    pseudo, start, end, _ = _layout(raw, ip_start)
    return ones_complement_checksum(pseudo + raw[start:end]) == 0


def _payload_start(raw: bytes, ip_start: int = 14) -> int:
    _, start, _, proto = _layout(raw, ip_start)
    return start + (8 if proto == _PROTO["udp"] else (raw[start + 12] >> 4) * 4)


def _udp(family: str, size: int, impaired: bool, **kw: object) -> list:
    client, server = _FAMILIES[family]
    return generate_udp_stream(
        client_ip=client, server_ip=server, num_data_packets=3,
        min_payload=size, max_payload=size, payload_distribution="fixed",
        config=UDPStreamConfig(
            base_time=1_700_000_000.0, seed=1,
            impairments=(ImpairmentConfig(payload_corruption_probability=1.0)
                         if impaired else None),
        ),
        **kw,
    ).packets


def _tcp(family: str, size: int, impaired: bool) -> list:
    client, server = _FAMILIES[family]
    return generate_tcp_stream(
        client_ip=client, server_ip=server, num_data_packets=3,
        min_payload=size, max_payload=size, payload_distribution="fixed",
        config=TCPStreamConfig(
            base_time=1_700_000_000.0, seed=1,
            client_options=None, server_options=None,
            payload_corruption_probability=1.0 if impaired else 0.0,
        ),
    ).packets


class TestTheFlipLandsInThePayload(unittest.TestCase):
    """The issue's grid: both transports, both families, either side of padding."""

    def _check(self, clean: bytes, corrupt: bytes, ip_start: int = 14) -> None:
        _, _, end, _ = _layout(clean, ip_start)
        differ = [i for i in range(len(clean)) if clean[i] != corrupt[i]]
        self.assertEqual(differ, [end - 1], "exactly the payload's last byte")
        self.assertGreaterEqual(end - 1, _payload_start(clean, ip_start))
        self.assertEqual(corrupt[end:], clean[end:], "the padding is unchanged")
        self.assertTrue(_checksum_ok(clean, ip_start))
        self.assertFalse(_checksum_ok(corrupt, ip_start), "the checksum no longer verifies")

    def test_udp(self) -> None:
        for family in _FAMILIES:
            for size in _SIZES:
                with self.subTest(family=family, size=size):
                    clean = _udp(family, size, impaired=False)
                    corrupt = _udp(family, size, impaired=True)
                    self.assertEqual(len(corrupt), len(clean))
                    for before, after in zip(clean, corrupt, strict=True):
                        self.assertTrue(after.label.startswith("CORRUPT["))
                        self._check(before.raw, after.raw)

    def test_tcp(self) -> None:
        for family in _FAMILIES:
            for size in _SIZES:
                with self.subTest(family=family, size=size):
                    clean = {p.label: p.raw for p in _tcp(family, size, impaired=False)}
                    corrupt = [p for p in _tcp(family, size, impaired=True)
                               if p.label.startswith("CORRUPT[")]
                    self.assertEqual(len(corrupt), 3)
                    for pkt in corrupt:
                        self._check(clean[pkt.label.replace("CORRUPT", "DATA")], pkt.raw)

    def test_the_issues_case_was_padded(self) -> None:
        """Five bytes over IPv4 UDP is a padded 60-byte frame: the case that hid it."""
        raw = _udp("IPv4", 5, impaired=True)[0].raw
        _, _, end, _ = _layout(raw, 14)
        self.assertEqual(len(raw), 60)
        self.assertLess(end, 60)


class TestWhereTheIPHeaderIs(unittest.TestCase):

    def _flipped_at_datagram_end(self, clean: bytes, corrupt: bytes, ip_start: int) -> None:
        _, _, end, _ = _layout(clean, ip_start)
        self.assertEqual([i for i in range(len(clean)) if clean[i] != corrupt[i]], [end - 1])

    def test_without_ethernet(self) -> None:
        clean = _udp("IPv4", 5, impaired=False, include_ethernet=False)[0].raw
        corrupt = _udp("IPv4", 5, impaired=True, include_ethernet=False)[0].raw
        self._flipped_at_datagram_end(clean, corrupt, ip_start=0)
        self.assertFalse(_checksum_ok(corrupt, ip_start=0))

    def test_behind_a_vlan_tag(self) -> None:
        clean = _udp("IPv4", 5, impaired=False, encap=VLANEncap(vid=5))[0].raw
        corrupt = _udp("IPv4", 5, impaired=True, encap=VLANEncap(vid=5))[0].raw
        self._flipped_at_datagram_end(clean, corrupt, ip_start=18)
        self.assertFalse(_checksum_ok(corrupt, ip_start=18))

    def test_under_esp_the_last_byte_of_the_datagram(self) -> None:
        """The inner packet is ciphertext there, and its last byte is flipped.

        Without an ICV, as the CLI's `--esp` builds it: an ICV stand-in comes
        from `os.urandom`, so two runs could not be compared byte by byte.
        """
        esp = ESPEncap(spi=1, src_ip="192.0.2.1", dst_ip="192.0.2.2")
        clean = _udp("IPv4", 5, impaired=False, encap=esp)[0].raw
        corrupt = _udp("IPv4", 5, impaired=True, encap=esp)[0].raw
        self._flipped_at_datagram_end(clean, corrupt, ip_start=14)

    def test_the_api_defaults_to_an_ethernet_frame(self) -> None:
        """`apply_datagram_impairments` called as before #200 finds the header too."""
        clean = _udp("IPv4", 5, impaired=False)
        corrupt = apply_datagram_impairments(
            list(clean), rng=random.Random(1),
            config=ImpairmentConfig(payload_corruption_probability=1.0),
        )
        for before, after in zip(clean, corrupt, strict=True):
            self._flipped_at_datagram_end(before.raw, after.raw, ip_start=14)


class TestTheVPNPayload(unittest.TestCase):

    def test_a_short_data_message_is_corrupted_in_its_payload(self) -> None:
        """Header, counter and one byte of ciphertext: 17 bytes, a padded frame."""
        def run(impaired: bool) -> list:
            return generate_vpn_stream(
                client_ip="10.0.0.2", server_ip="10.0.0.1", epochs=1,
                packets_per_epoch=4, min_payload=1, max_payload=1, seed=3,
                base_time=1_700_000_000.0,
                config=VPNConfig(impairments=ImpairmentConfig(
                    payload_corruption_probability=1.0) if impaired else None),
            ).packets
        # Each run draws its ciphertext from the same RNG as the impairments,
        # so the runs differ; each corrupted datagram is checked on its own.
        corrupt = [p for p in run(True) if p.label.startswith("CORRUPT[DATA")]
        self.assertTrue(corrupt)
        for pkt in corrupt:
            _, _, end, _ = _layout(pkt.raw, 14)
            self.assertEqual(len(pkt.raw), 60, "a padded frame")
            self.assertLess(end, 60)
            self.assertFalse(_checksum_ok(pkt.raw), "the payload, not the padding")


class TestFamiliesAreWhatTheyClaim(unittest.TestCase):

    def test_addresses(self) -> None:
        for family, (client, _) in _FAMILIES.items():
            version = ipaddress.ip_address(client).version
            self.assertEqual(family, f"IPv{version}")


if __name__ == "__main__":
    unittest.main()
