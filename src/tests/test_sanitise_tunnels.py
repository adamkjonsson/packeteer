"""Redacting the inner packet of an encapsulation (#151).

The bug this covers: `_sanitise_packet` recursed into a nested tunnel over a
hand-written list of keys that was missing three of the six that nest one.
`parse` puts a whole inner packet under `vxlan`, `geneve` and `gtpu` exactly as
it does under `ipip`, `gre` and `etherip`, so for those three nothing inside
the tunnel was redacted — while every outer field was, and no warning fired,
because all three are in `_STRUCTURAL_KEYS` and the packet *was* decoded.

The test names all six, not just the three that leaked: a rule stated only
where it once failed is a regression test, and the thing worth asserting here
is the rule.
"""
from __future__ import annotations

import json
import unittest
import warnings
from pathlib import Path

from packeteer.generate import PacketBuilder
from packeteer.parse import parse_packet
from packeteer.parse.core import _packet_to_spec
from packeteer.sanitise import _NESTING_TUNNEL_KEYS, _STRUCTURAL_KEYS, sanitise

#: Outer addresses — the capture point's own, and redacted before this bug.
_OUTER = {"src": "203.0.113.9", "dst": "198.51.100.7"}
#: Inner addresses — the carried traffic, and what leaked.  Deliberately
#: globally routable, so a leak is unmistakable.
_INNER = {"src": "8.8.8.8", "dst": "1.1.1.1"}
_INNER_MACS = {"src_mac": "de:ad:be:ef:00:01", "dst_mac": "de:ad:be:ef:00:02"}


def _build(kind: str) -> bytes:
    b = PacketBuilder().ethernet(src_mac="02:00:00:00:aa:01",
                                 dst_mac="02:00:00:00:aa:02")
    if kind == "vxlan":
        b = b.ip(**_OUTER).udp(dst_port=4789).vxlan(vni=7).ethernet(**_INNER_MACS)
    elif kind == "geneve":
        b = b.ip(**_OUTER).udp(dst_port=6081).geneve(vni=7).ethernet(**_INNER_MACS)
    elif kind == "gtpu":
        b = b.ip(**_OUTER).udp(dst_port=2152).gtpu(teid=7)
    elif kind == "gre":
        b = b.ip(**_OUTER).gre()
    elif kind == "etherip":
        b = b.ip(**_OUTER).etherip().ethernet(**_INNER_MACS)
    else:
        raise AssertionError(f"no fixture for {kind}")
    return b.ip(**_INNER).tcp(dst_port=8080).build()


def _sanitised(kind: str) -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        spec = _packet_to_spec(parse_packet(_build(kind), decode_app=False))
        return json.dumps(sanitise({"packets": [spec]}))


class TestTheInnerPacketIsRedacted(unittest.TestCase):
    """An encapsulation is not a place addresses get to hide."""

    def test_inner_addresses_do_not_survive(self) -> None:
        for kind in ("vxlan", "geneve", "gtpu", "gre", "etherip"):
            blob = _sanitised(kind)
            for address in _INNER.values():
                with self.subTest(encapsulation=kind, address=address):
                    self.assertNotIn(address, blob)

    def test_inner_macs_do_not_survive(self) -> None:
        """VXLAN, Geneve and EtherIP carry a whole inner Ethernet frame."""
        for kind in ("vxlan", "geneve", "etherip"):
            blob = _sanitised(kind)
            for mac in _INNER_MACS.values():
                with self.subTest(encapsulation=kind, mac=mac):
                    self.assertNotIn(mac, blob)

    def test_the_outer_packet_is_still_redacted(self) -> None:
        """The bug left the outer header correct, so this is what stayed true."""
        for kind in ("vxlan", "geneve", "gtpu", "gre", "etherip"):
            blob = _sanitised(kind)
            for address in _OUTER.values():
                with self.subTest(encapsulation=kind, address=address):
                    self.assertNotIn(address, blob)


class TestTheTwoKeyListsCannotDrift(unittest.TestCase):
    """What actually caused #151: the same fact written down twice.

    All three keys were added to `_STRUCTURAL_KEYS` when the encapsulations
    landed and forgotten in the recursion list, which is why the leak was
    silent — `_warn_undecoded` consults the first list.
    """

    def test_every_nesting_key_is_structural(self) -> None:
        self.assertLessEqual(_NESTING_TUNNEL_KEYS, _STRUCTURAL_KEYS)

    def test_every_parser_nesting_key_is_listed(self) -> None:
        """The parser is the authority on which keys nest a whole packet.

        `to_config` writes `config[key] = inner` for each of these.  If one is
        added there and not here, the inner packet stops being redacted — so
        this asserts against the parser rather than against a copy of the list.
        """
        from packeteer.parse import to_config

        source = Path(to_config.__file__).read_text(encoding="utf-8")
        nesting = {
            key for key in _STRUCTURAL_KEYS
            if f'config["{key}"] = inner' in source
        }
        self.assertTrue(nesting, "the detection itself should find something")
        self.assertLessEqual(
            nesting, _NESTING_TUNNEL_KEYS,
            "an encapsulation nests an inner packet but is not recursed into",
        )


if __name__ == "__main__":
    unittest.main()
