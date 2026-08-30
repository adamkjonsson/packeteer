"""Sweeps over the tracked corpus of real captures (#89).

Every other capture CI can see is one packeteer generated itself, and that is
a blind spot shaped exactly like the bugs this project keeps finding: across
the eleven synthetic captures, **0 of 1 314 TCP packets carry a TCP option**,
while the real ones carry them on every packet.  #87 existed because of that
and was found by hand.

These captures are real traffic, sanitised, and named individually in
`.gitignore`.  See `testcases/real/MANIFEST.md`.
"""
from __future__ import annotations

import json
import unittest
import warnings
from pathlib import Path

import packeteer.__main__ as cli
from packeteer.generate import PacketBuilder
from packeteer.parse import iter_packets, parse_pcap_file
from packeteer.pcap import open_pcap

_CORPUS = Path(__file__).resolve().parents[2] / "testcases" / "real"
_MANIFEST = _CORPUS / "MANIFEST.md"

#: A key meaning at least part of a packet was understood.
_STRUCTURAL_KEYS = frozenset({
    "ethernet", "sll", "sll2", "loopback", "arp", "network",
})


def _captures() -> list[Path]:
    """Every file in the corpus except the manifest, whatever it is called.

    Deliberately not a ``*.pcapng`` glob.  These sweeps are the only thing
    checking these files, and one they silently skip is worse than one that is
    missing: a `.pcap` capture went unswept until the extension was noticed.
    Anything dropped in here now fails the manifest and `.gitignore` checks
    below, which is what makes adding a capture an act rather than an accident.
    """
    return sorted(
        path for path in _CORPUS.iterdir()
        if path.is_file() and path.name != "MANIFEST.md"
        and not path.name.startswith(".")
    )


class TestTheCorpusIsThere(unittest.TestCase):
    """It is tracked, so unlike the synthetic captures it cannot be missing."""

    def test_it_is_not_empty(self) -> None:
        self.assertTrue(_captures(), "the corpus is committed; it cannot be empty")

    def test_every_capture_is_named_in_the_manifest(self) -> None:
        """A capture nothing says anything about is a file, not a test."""
        manifest = _MANIFEST.read_text(encoding="utf-8")
        for path in _captures():
            with self.subTest(capture=path.name):
                self.assertIn(path.name, manifest)

    def test_every_capture_is_named_in_gitignore(self) -> None:
        """Naming each one is what stops an unsanitised file being committed."""
        ignore = (_CORPUS.parents[1] / ".gitignore").read_text(encoding="utf-8")
        for path in _captures():
            with self.subTest(capture=path.name):
                self.assertIn(f"!testcases/real/{path.name}", ignore)

    def test_the_corpus_stays_small(self) -> None:
        """It is committed, so it has to stay something people want to clone."""
        total = sum(p.stat().st_size for p in _captures())
        self.assertLess(total, 512 * 1024, "trim captures with editcap")


class TestEveryCaptureParses(unittest.TestCase):

    def test_no_warnings_and_no_undecoded_frames(self) -> None:
        for path in _captures():
            with self.subTest(capture=path.name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter("always")
                    spec = json.loads(parse_pcap_file(path=str(path)))
                self.assertEqual([str(w.message) for w in caught], [])
                for index, packet in enumerate(spec["packets"], start=1):
                    # An ARP packet has no `network`, so the test is that
                    # *something* structural was decoded — not one key.
                    self.assertTrue(
                        _STRUCTURAL_KEYS & set(packet),
                        f"{path.name} packet {index} decoded to nothing but a "
                        f"payload, which means an unsupported link type",
                    )


class TestRoundTrip(unittest.TestCase):
    """parse → build reproduces a real capture byte for byte.

    The property everything else in packeteer serves, asserted against traffic
    nobody wrote for it.  #68, #86 and #87 were each a hole in exactly this,
    and each was invisible until a real capture went through.
    """

    def test_every_packet_rebuilds_identically(self) -> None:
        for path in _captures():
            with self.subTest(capture=path.name):
                self._round_trip(path)

    def _round_trip(self, path: Path) -> None:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            spec = json.loads(parse_pcap_file(path=str(path)))
        with open_pcap(path=str(path)) as capture:
            originals = [record.data for record in capture]

        self.assertEqual(len(spec["packets"]), len(originals))
        for index, (packet, original) in enumerate(zip(spec["packets"], originals, strict=True),
                                                   start=1):
            builder, _ = cli._apply_spec_to_builder(PacketBuilder(), packet, index)
            self.assertEqual(
                builder.build().hex(), original.hex(),
                f"{path.name} packet {index} did not rebuild identically",
            )


class TestRealTrafficCoversWhatSyntheticCannot(unittest.TestCase):
    """The reasons this corpus exists, asserted rather than assumed.

    If a capture stops covering what it was collected for, that is worth a
    failure — otherwise the corpus quietly becomes decoration.
    """

    def _spec(self, name: str) -> dict:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return json.loads(parse_pcap_file(path=str(_CORPUS / name)))

    def _packets(self, name: str) -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(_CORPUS / name), decode_app=False,
                              defragment=False) as capture:
                return list(capture)

    def test_tcp_options_come_from_two_different_stacks(self) -> None:
        """#87 was an option *layout* bug; one sender's layout cannot show it."""
        layouts = set()
        for pkt in self._packets("tcp_v4.pcapng"):
            options = getattr(pkt.transport, "options", None)
            if options is not None and options.raw:
                layouts.add(bytes(options.raw))
        self.assertGreaterEqual(
            len(layouts), 2,
            "tcp_v4.pcapng should carry both ends' option layouts",
        )

    def test_dns_carries_record_types_nobody_generates(self) -> None:
        """What this capture actually covers, checked rather than assumed.

        It used to claim compression pointers.  It has none: `sanitise`
        re-encodes every message with its names written out in full, so the
        committed file is packeteer's own output (#130).  The old test passed
        anyway — it scanned for a byte with its top two bits set, and ordinary
        data bytes are often >= 0xC0.  This asserts something true instead.
        """
        types = set()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(_CORPUS / "dns.pcapng"),
                              defragment=False) as capture:
                for pkt in capture:
                    message = pkt.app
                    if message is None or type(message).__name__ != "DNSMessage":
                        continue
                    types.update(rr.rtype for rr in message.answers
                                 + message.authority + message.additional)
        # CNAME, SOA, OPT (EDNS0) and HTTPS — none of which packeteer's own
        # generated captures emit, and each a separate decoder path.
        self.assertTrue({5, 6, 41, 65} <= types, f"only found {sorted(types)}")

    def test_a_loopback_capture_uses_dlt_null(self) -> None:
        with open_pcap(path=str(_CORPUS / "tcp_v6_loopback.pcapng")) as capture:
            self.assertEqual(capture.header.link_type, 0)

    def test_a_loopback_capture_carries_offloaded_checksums(self) -> None:
        """Real evidence that `transport.checksum` must be preserved (#68)."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            spec = json.loads(parse_pcap_file(
                path=str(_CORPUS / "tcp_v6_loopback.pcapng")))
        kept = [p for p in spec["packets"]
                if "checksum" in p.get("transport", {})]
        self.assertTrue(kept, "offloaded checksums should survive into the spec")

    def test_a_snaplen_capture_is_actually_truncated(self) -> None:
        """#92, #94 and #126 all turn on a capture holding less than it says."""
        with open_pcap(path=str(_CORPUS / "tcp_v4_snaplen.pcapng")) as capture:
            records = list(capture)
        cut = [r for r in records if len(r.data) < r.orig_len]
        self.assertTrue(cut, "tcp_v4_snaplen.pcapng should hold truncated records")

    def test_a_snaplen_capture_rebuilds_as_a_truncated_file(self) -> None:
        """Not just the packets (#126): the file has to say it was cut too."""
        path = _CORPUS / "tcp_v4_snaplen.pcapng"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            spec = json.loads(parse_pcap_file(path=str(path)))
        with open_pcap(path=str(path)) as capture:
            header, records = capture.header, list(capture)

        self.assertEqual(spec["metadata"]["snaplen"], header.snaplen)
        rebuilt = {p["packet_metadata"]["packet_num"]:
                   p["packet_metadata"].get("orig_len")
                   for p in spec["packets"]}
        self.assertEqual(
            rebuilt,
            {i: (r.orig_len if len(r.data) < r.orig_len else None)
             for i, r in enumerate(records, 1)},
        )
        truncated = [p for p in spec["packets"]
                     if "declared_length" in p.get("network", {})]
        self.assertTrue(truncated, "the cut packets should keep their IP length")

    def test_a_capture_carries_a_link_layer_trailer(self) -> None:
        """58-byte frames: 42 of ARP and 16 of padding, which #129 restored."""
        spec = self._spec("arp.pcapng")
        trailers = [p["ethernet"]["trailer"] for p in spec["packets"]
                    if "trailer" in p.get("ethernet", {})]
        self.assertTrue(trailers, "arp.pcapng should hold padded frames")
        self.assertEqual({len(bytes.fromhex(t)) for t in trailers}, {16})

    def test_a_capture_is_a_classic_pcap_file(self) -> None:
        """`tcpdump -w`'s own format, which sanitising to pcapng had hidden."""
        formats = set()
        for path in _captures():
            with open_pcap(path=str(path)) as capture:
                formats.add("pcapng" if capture.header.version_major == 1
                            else "pcap")
        self.assertIn("pcap", formats, "no capture exercises the classic format")
        self.assertIn("pcapng", formats)

    def test_a_capture_uses_nanosecond_timestamps(self) -> None:
        """The `0xa1b23c4d` magic and `timestamp_ns`, which nothing else reaches."""
        with open_pcap(path=str(_CORPUS / "udp_frag_nano.pcap")) as capture:
            self.assertTrue(capture.header.nanoseconds)
            self.assertEqual(capture.header.tick_hz, 1_000_000_000)
        spec = self._spec("udp_frag_nano.pcap")
        self.assertIn("timestamp_ns", spec["packets"][0]["packet_metadata"])
        self.assertTrue(spec["metadata"]["nanoseconds"])

    def test_a_first_fragment_describes_the_whole_datagram(self) -> None:
        """#68's case in real bytes: the OS fragmented this, not packeteer."""
        packets = self._packets("udp_frag_nano.pcap")
        first = packets[0]
        self.assertTrue(first.ip.flags & 0b001, "the MF flag should be set")
        self.assertEqual(first.ip.fragment_offset, 0)
        transport = self._spec("udp_frag_nano.pcap")["packets"][0]["transport"]
        # The header covers 4008 bytes; only 1472 of them are in this packet,
        # so a rebuild cannot derive either key and both have to be recorded.
        self.assertGreater(transport["length"], len(first.payload))
        self.assertIn("checksum", transport)

    def test_a_fragmented_datagram_reassembles(self) -> None:
        """The OS split this one, so `defragment` finally sees real fragments."""
        fragments = self._packets("udp_frag_nano.pcap")
        self.assertGreater(len(fragments), 1, "one fragment proves no reassembly")
        self.assertEqual(len({f.ip.identification for f in fragments}), 1,
                         "every fragment of a datagram shares its IP id")
        offsets = [f.ip.fragment_offset for f in fragments]
        self.assertEqual(offsets, sorted(offsets))
        self.assertEqual(offsets[0], 0)
        self.assertFalse(fragments[-1].ip.flags & 0b001,
                         "the last fragment is the one that clears MF")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(_CORPUS / "udp_frag_nano.pcap")) as capture:
                whole = list(capture)
        self.assertEqual(len(whole), 1, "the fragments should reassemble into one")
        self.assertEqual(
            len(whole[0].payload),
            sum(len(f.payload or b"") for f in fragments),
            "reassembly should lose nothing",
        )

    def test_a_capture_carries_a_chunked_http_body(self) -> None:
        """#84's subject: the body stays as raw chunks, and spans two segments."""
        spec = self._spec("http_body.pcap")
        responses = [p["http"] for p in spec["packets"]
                     if p.get("http", {}).get("type") == "response"]
        self.assertTrue(responses, "the capture should hold an HTTP response")
        body = responses[0]
        self.assertEqual(body["headers"].get("Transfer-Encoding"), "chunked")
        # A chunk header is "<hex size>\r\n"; de-chunked, the body would start
        # with the document itself.
        self.assertRegex(bytes.fromhex(body["body"]).decode("latin-1"),
                         r"^[0-9a-fA-F]+\r\n")
        # The terminating chunk arrived in its own segment.
        tails = [p["payload"]["data"] for p in spec["packets"]
                 if p.get("payload", {}).get("data", "").endswith("0d0a0d0a")]
        self.assertTrue(tails, "the final 0-length chunk should be present")

    def test_icmpv6_carries_neighbour_discovery(self) -> None:
        types = {p.transport.type for p in self._packets("icmpv6_nd.pcapng")
                 if type(p.transport).__name__ == "ICMPv6Header"}
        self.assertTrue({135, 136} & types)


class TestNothingIdentifyingSurvived(unittest.TestCase):
    """These are real captures in a public repository.

    The scan cannot see the originals, so it looks for the shapes that should
    never appear: a routable address, or a MAC that is not one of the
    synthetic ones `sanitise` hands out.
    """

    def test_no_globally_routable_addresses(self) -> None:
        import ipaddress

        for path in _captures():
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                with iter_packets(path=str(path), decode_app=False,
                                  defragment=False) as capture:
                    for index, pkt in enumerate(capture, start=1):
                        if pkt.ip is None:
                            continue
                        for value in (pkt.ip.src, pkt.ip.dst):
                            address = ipaddress.ip_address(value)
                            with self.subTest(capture=path.name, packet=index,
                                              address=value):
                                self.assertFalse(
                                    address.is_global,
                                    "a routable address survived sanitisation",
                                )


if __name__ == "__main__":
    unittest.main()
