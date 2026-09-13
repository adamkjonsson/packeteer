"""parse -> build reproduces a tunnelled frame, for every encapsulation (#153, #154).

Three bugs were found at once by pointing packeteer at real tunnelled traffic
for the first time (#127), and all three were the same absence: nothing
round-tripped an encapsulated packet.  Each module had tests that built a
frame and parsed it back — which cannot see a field the serialiser drops,
because the value it compares against is the one packeteer computed.

- #153: the outer UDP checksum was recorded by `parse` and not passed to the
  builder by VXLAN, Geneve or GTP-U, so every tunnelled packet whose sender
  computed one came back with a different checksum.
- #154: no inner-frame serialiser wrote an inner ARP, so a VXLAN frame
  carrying one parsed to `['ethernet', 'vni']` and could not be rebuilt at
  all — silently.

Driving the sweep from a table, rather than adding a case to each module's own
file, is the point: the next encapsulation is covered by being listed.
"""
from __future__ import annotations

import json
import unittest
import warnings

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import UnserialisedInnerLayerWarning, parse_pcap_file
from packeteer.pcap import write_pcap

_OUTER = {"src": "10.0.0.1", "dst": "10.0.0.2"}
_INNER = {"src": "192.168.1.1", "dst": "192.168.1.2"}
#: A checksum no recomputation would arrive at, so a rebuild that recomputes
#: rather than preserves is unmistakable.  This is #153's whole surface.
_ODD_CHECKSUM = 0x1234


def _with_inner_tcp(b: PacketBuilder) -> PacketBuilder:
    return b.ip(**_INNER).tcp(dst_port=80)


def _encapsulations() -> dict[str, PacketBuilder]:
    """One frame per encapsulation, each carrying an inner TCP segment."""
    base = lambda: PacketBuilder().ethernet().ip(**_OUTER)  # noqa: E731
    return {
        "vxlan": _with_inner_tcp(
            base().udp(dst_port=4789, checksum=_ODD_CHECKSUM)
            .vxlan(vni=7).ethernet()),
        "geneve": _with_inner_tcp(
            base().udp(dst_port=6081, checksum=_ODD_CHECKSUM)
            .geneve(vni=7).ethernet()),
        "gtpu": _with_inner_tcp(
            base().udp(dst_port=2152, checksum=_ODD_CHECKSUM).gtpu(teid=7)),
        "gre": _with_inner_tcp(base().gre()),
        "etherip": _with_inner_tcp(base().etherip().ethernet()),
        "ipip": _with_inner_tcp(base()),
    }


def _round_trip(raw: bytes, tmp: str) -> tuple[bytes, list[warnings.WarningMessage]]:
    write_pcap([(raw, 0, 0)], path=tmp)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        spec = json.loads(parse_pcap_file(path=tmp))
        builder, _ = cli._apply_spec_to_builder(
            PacketBuilder(), spec["packets"][0], 1)
    return builder.build(), list(caught)


class TestEveryEncapsulationRebuildsIdentically(unittest.TestCase):

    def setUp(self) -> None:
        import tempfile

        self._dir = tempfile.TemporaryDirectory()
        self.tmp = f"{self._dir.name}/t.pcap"
        self.addCleanup(self._dir.cleanup)

    def test_inner_tcp_survives(self) -> None:
        for name, builder in _encapsulations().items():
            with self.subTest(encapsulation=name):
                raw = builder.build()
                rebuilt, caught = _round_trip(raw, self.tmp)
                self.assertEqual([str(w.message) for w in caught], [])
                self.assertEqual(rebuilt.hex(), raw.hex())

    def test_a_preserved_outer_checksum_is_not_recomputed(self) -> None:
        """#153.  Only the UDP-borne encapsulations have an outer checksum."""
        for name in ("vxlan", "geneve", "gtpu"):
            with self.subTest(encapsulation=name):
                raw = _encapsulations()[name].build()
                # Outer UDP checksum: ethernet 14 + IPv4 20 + 6.
                self.assertEqual(raw[40:42].hex(), "1234", "fixture is wrong")
                rebuilt, _ = _round_trip(raw, self.tmp)
                self.assertEqual(
                    rebuilt[40:42].hex(), "1234",
                    "the recorded checksum should be replayed, not recomputed",
                )

    def test_an_inner_arp_survives(self) -> None:
        """#154.  VXLAN, Geneve and EtherIP carry a whole inner Ethernet frame.

        An Ethernet overlay is where ARP lives — it is how hosts on the
        overlay find each other — so this is not an exotic inner payload.
        """
        frames = {
            "vxlan": (PacketBuilder().ethernet().ip(**_OUTER)
                      .udp(dst_port=4789).vxlan(vni=7)
                      .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
                      .arp(sender_ip="192.168.1.1", target_ip="192.168.1.2")),
            "geneve": (PacketBuilder().ethernet().ip(**_OUTER)
                       .udp(dst_port=6081).geneve(vni=7)
                       .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
                       .arp(sender_ip="192.168.1.1", target_ip="192.168.1.2")),
            "etherip": (PacketBuilder().ethernet().ip(**_OUTER).etherip()
                        .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
                        .arp(sender_ip="192.168.1.1", target_ip="192.168.1.2")),
        }
        for name, builder in frames.items():
            with self.subTest(encapsulation=name):
                raw = builder.build()
                rebuilt, caught = _round_trip(raw, self.tmp)
                self.assertEqual([str(w.message) for w in caught], [])
                self.assertEqual(rebuilt.hex(), raw.hex())


class TestAnUnserialisedInnerLayerIsLoud(unittest.TestCase):
    """#154's other half: the omission was silent, which is why it lasted.

    A frame whose inner payload vanished is indistinguishable, in a spec, from
    one that never had it.  `_warn_undecoded` already makes that argument for
    an outer frame; this is the same guard one layer in.
    """

    def test_a_dropped_inner_layer_warns(self) -> None:
        import tempfile

        from packeteer.parse import to_config

        raw = (PacketBuilder().ethernet().ip(**_OUTER)
               .udp(dst_port=4789).vxlan(vni=7)
               .ethernet(dst_mac="ff:ff:ff:ff:ff:ff")
               .arp(sender_ip="192.168.1.1", target_ip="192.168.1.2").build())

        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/t.pcap"
            write_pcap([(raw, 0, 0)], path=path)

            original = to_config._apply_arp
            to_config._apply_arp = lambda inner, hdr: None
            try:
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    parse_pcap_file(path=path)
            finally:
                to_config._apply_arp = original

        hits = [w for w in caught
                if issubclass(w.category, UnserialisedInnerLayerWarning)]
        self.assertTrue(hits, "dropping an inner layer should warn")
        self.assertEqual(hits[0].message.layers, ("arp",))

    def test_a_complete_frame_does_not_warn(self) -> None:
        """The guard has to be quiet on everything the serialisers do handle."""
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = f"{directory}/t.pcap"
            for name, builder in _encapsulations().items():
                with self.subTest(encapsulation=name):
                    write_pcap([(builder.build(), 0, 0)], path=path)
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter("always")
                        parse_pcap_file(path=path)
                    self.assertEqual([str(w.message) for w in caught], [])


if __name__ == "__main__":
    unittest.main()
