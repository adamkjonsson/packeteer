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


def _every_address(pkt: object, depth: int = 0) -> list[tuple[int, str]]:
    """Every IP address in *pkt*, following tunnels to whatever depth.

    `pkt.ip` on a tunnelled packet is the **outer** header, so a scan that
    reads only that guards the one header least likely to be the problem: the
    outer addresses of a tunnel are the capture point's own, while the inner
    ones are the traffic being carried.  #151 was exactly this — `sanitise`
    left VXLAN, Geneve and GTP-U inner addresses untouched, and this sweep
    could not see it.

    Returns (depth, address) pairs so a failure says which layer leaked.
    """
    found: list[tuple[int, str]] = []
    ip = getattr(pkt, "ip", None)
    if ip is not None:
        found.extend((depth, value) for value in (ip.src, ip.dst))
    inner = getattr(pkt, "tunneled", None)
    if inner is not None:
        found.extend(_every_address(inner, depth + 1))
    return found


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
        """It is committed, so it has to stay something people want to clone.

        Raised from 512 KiB to 1 MiB when the receiver-side TCP captures
        (#158, #160, #161) took it past the first figure: each is a whole
        64 KiB transfer, which is what it takes for a stack to show a fast
        retransmit, and a slice of one would not hold the handshake that
        tells a reader the ISN.
        """
        total = sum(p.stat().st_size for p in _captures())
        self.assertLess(total, 1024 * 1024, "trim captures with editcap")


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

    def test_a_capture_was_taken_at_nanosecond_resolution(self) -> None:
        """#127: the corpus had the nanosecond *format* and not the resolution.

        `udp_frag_nano.pcap` was converted with `editcap -F nsecpcap` from a
        microsecond capture, so every sub-microsecond digit in it is zero — it
        exercises the format and says nothing about a capture clock.  macOS
        BPF has no nanosecond mode, so closing this needed a Linux capture.
        """
        with open_pcap(path=str(_CORPUS / "tcp_lossy_ts.pcap")) as capture:
            fractions = [record.ts_frac % 1000 for record in capture]
        self.assertTrue(fractions)
        self.assertTrue(
            all(fractions),
            "every record should carry a non-zero sub-microsecond part",
        )


class TestTheCorpusReachesTheEncapsulations(unittest.TestCase):
    """#127's largest gap, asserted per capture.

    Nine encapsulation modules had no real traffic at all, and collecting it
    found #153, #154 and #155 within the hour.  Each test names the decoder its
    capture exercises, so a file that stops covering what it was collected for
    fails rather than quietly becoming decoration.
    """

    def _packets(self, name: str) -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(_CORPUS / name), decode_app=False,
                              defragment=False) as capture:
                return list(capture)

    def test_each_tunnel_capture_decodes_its_encapsulation(self) -> None:
        for name, attribute in (("vxlan.pcap", "vxlan"),
                                ("geneve.pcap", "geneve"),
                                ("gre.pcap", "gre"),
                                ("ipip.pcap", "ipip")):
            with self.subTest(capture=name):
                decoded = [p for p in self._packets(name)
                           if getattr(p, attribute, None)]
                self.assertTrue(decoded, f"{name} should decode as {attribute}")

    def test_a_tunnel_capture_carries_an_inner_frame(self) -> None:
        """The reason to capture on the underlay: the whole stack is in the file."""
        for name in ("vxlan.pcap", "geneve.pcap", "gre.pcap", "ipip.pcap"):
            with self.subTest(capture=name):
                inner = [p.tunneled for p in self._packets(name)
                         if getattr(p, "tunneled", None) is not None]
                self.assertTrue(inner, f"{name} should carry inner packets")
                self.assertTrue(any(p.ip is not None for p in inner),
                                "at least one inner frame should reach IP")

    def test_an_overlay_carries_inner_arp(self) -> None:
        """#154's case in real bytes: ARP is how hosts on an overlay find each other."""
        for name in ("vxlan.pcap", "geneve.pcap"):
            with self.subTest(capture=name):
                arps = [p for p in self._packets(name)
                        if getattr(getattr(p, "tunneled", None), "arp", None)]
                self.assertTrue(arps, f"{name} should carry an inner ARP")

    def test_a_capture_is_vlan_tagged(self) -> None:
        tagged = [p for p in self._packets("vlan.pcap")
                  if getattr(p.ethernet, "vlan_tag", None) is not None]
        self.assertTrue(tagged, "vlan.pcap should carry 802.1Q tags")
        self.assertEqual({p.ethernet.vlan_tag.vid for p in tagged}, {100})

    def test_a_capture_carries_a_hop_by_hop_header(self) -> None:
        """#155's case: an extension header, not a field, and it must rebuild."""
        found = False
        for name in ("vlan.pcap", "ipv6_frag.pcap"):
            spec = json.loads(self._spec_text(name))
            found = found or any(
                "hop_by_hop_options" in p.get("network", {})
                for p in spec["packets"])
        self.assertTrue(found, "no capture carries hop-by-hop options")

    def _spec_text(self, name: str) -> str:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return parse_pcap_file(path=str(_CORPUS / name))

    def test_an_ipv6_datagram_is_fragmented_by_the_kernel(self) -> None:
        """The IPv6 half of #68; `udp_frag_nano.pcap` is the IPv4 half."""
        spec = json.loads(self._spec_text("ipv6_frag.pcap"))
        fragments = [p for p in spec["packets"]
                     if "fragment" in p.get("network", {})]
        self.assertGreater(len(fragments), 1,
                           "one fragment proves no fragmentation")
        identifications = {p["network"]["fragment"]["identification"]
                           for p in fragments}
        self.assertEqual(len(identifications), 1,
                         "every fragment of a datagram shares its id")

    def test_a_capture_holds_a_real_sctp_association(self) -> None:
        packets = self._packets("sctp.pcap")
        chunk_bearing = [p for p in packets
                         if type(p.transport).__name__ == "SCTPHeader"]
        self.assertTrue(chunk_bearing, "sctp.pcap should decode as SCTP")

    def test_both_linux_cooked_link_types_are_present(self) -> None:
        """Two encodings of the same idea; the corpus had neither."""
        for name, expected in (("sll_any.pcap", 113), ("sll2_any.pcap", 276)):
            with (self.subTest(capture=name),
                  open_pcap(path=str(_CORPUS / name)) as capture):
                self.assertEqual(capture.header.link_type, expected)

    def test_a_capture_is_raw_ip(self) -> None:
        """#152's case: a link type with no link-layer header at all."""
        with open_pcap(path=str(_CORPUS / "ipip_raw.pcap")) as capture:
            self.assertEqual(capture.header.link_type, 101)
        spec = json.loads(self._spec_text("ipip_raw.pcap"))
        for packet in spec["packets"]:
            self.assertNotIn("ethernet", packet)
            self.assertIn("network", packet)


class _TimestampedSession(unittest.TestCase):
    """Helpers for the captures where both ends carry the Timestamps option."""

    def _fields(self, name: str) -> list:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            with iter_packets(path=str(_CORPUS / name), decode_app=False,
                              defragment=False) as capture:
                return list(capture)

    @staticmethod
    def _tsval(pkt: object) -> int | None:
        options = getattr(getattr(pkt, "transport", None), "options", None)
        timestamps = getattr(options, "timestamps", None)
        return None if timestamps is None else timestamps[0]

    def _data_segments(self, name: str) -> list:
        """Return the bulk sender's data segments, in capture order."""
        packets = self._fields(name)
        return [p for p in packets
                if getattr(p, "payload", None) and self._tsval(p) is not None
                and p.transport.src_port == self._bulk_sender(packets)]

    @staticmethod
    def _bulk_sender(packets: list) -> int:
        """Return the port that sent the most bytes.

        Not simply the first data segment's port: the client opens with a
        five-byte request, so "whoever sent data first" is the receiver of
        everything these tests are about.
        """
        sent: dict[int, int] = {}
        for pkt in packets:
            if getattr(pkt, "payload", None):
                port = pkt.transport.src_port
                sent[port] = sent.get(port, 0) + len(pkt.payload)
        return max(sent, key=lambda port: sent[port])

    @staticmethod
    def _after(a: int, b: int) -> bool:
        """Return whether sequence number *a* is after *b* (RFC 1982)."""
        return 0 < ((a - b) & 0xFFFFFFFF) < (1 << 31)

    def _replay(
        self, name: str, honour_checksums: bool = False,
    ) -> tuple[list, list[dict], list[dict]]:
        """Replay *name* as its receiver saw it.

        Returns the packets, the holes and the fills.  A hole opens when a
        data segment arrives past `rcv_nxt` and closes when a segment arrives
        at the sequence number it started at; a fill is any in-order arrival
        that had segments held beyond it, recorded with those segments.  Every
        comparison is modulo 2**32, since `tcp_wrap_ts.pcap` crosses it.

        With *honour_checksums*, a segment whose transport checksum was wrong
        on the wire — which is what a recorded `transport.checksum` means
        after parsing, see `_clear_derivable_transport_fields` — is dropped
        the way the receiver dropped it.  Only meaningful for a capture taken
        with checksum offload off; on the others every checksum is wrong.
        """
        packets = self._fields(name)
        sender = self._bulk_sender(packets)
        data = [(index, pkt) for index, pkt in enumerate(packets)
                if getattr(pkt, "payload", None) and self._tsval(pkt) is not None
                and pkt.transport.src_port == sender]
        self.assertTrue(data, "the capture should hold data segments")

        rcv_nxt = data[0][1].transport.seq
        held: dict[int, tuple[int, object]] = {}
        holes: list[dict] = []
        fills: list[dict] = []
        for index, pkt in data:
            if honour_checksums and pkt.transport.checksum is not None:
                continue
            seq = pkt.transport.seq
            if seq == rcv_nxt:
                beyond = [entry for s, entry in held.items() if self._after(s, seq)]
                if beyond:
                    fills.append({"index": index, "segment": pkt, "beyond": beyond})
                if holes and holes[-1]["start"] == seq:
                    holes[-1]["filled"] = index
                rcv_nxt = (rcv_nxt + len(pkt.payload)) & 0xFFFFFFFF
                while rcv_nxt in held:
                    rcv_nxt = (rcv_nxt + len(held.pop(rcv_nxt)[1].payload)) & 0xFFFFFFFF
            elif self._after(seq, rcv_nxt):
                if not held:
                    holes.append({"start": rcv_nxt, "opened": index})
                held.setdefault(seq, (index, pkt))
        self.assertFalse(held, "the transfer should have completed")
        return packets, holes, fills

    def _covering_ack(self, packets: list, index: int, sender: int) -> object | None:
        """Return the first receiver ACK after *index* that covers that segment."""
        segment = packets[index]
        end = (segment.transport.seq + len(segment.payload)) & 0xFFFFFFFF
        for later in packets[index + 1:]:
            options = getattr(later.transport, "options", None)
            if (later.transport.src_port == sender
                    or getattr(options, "timestamps", None) is None):
                continue
            if later.transport.ack == end or self._after(later.transport.ack, end):
                return later
        return None


class TestALossyTimestampedSession(_TimestampedSession):
    """What `tcp_lossy_ts.pcap` and `tcp_dup_ts.pcap` are for (#149).

    #90 made every generated resend carry a fresh clock, which is what lets an
    analyser tell a retransmission from a duplicate.  Nothing said a real stack
    does the same: the corpus's one complete session, `tcp_v4.pcapng`, loses
    nothing, and every capture that repeats a segment predates the option.
    These two files are that evidence, and each test below is one of the three
    properties #149 named.
    """

    def test_both_ends_negotiated_timestamps(self) -> None:
        """Without that, none of the rest of this file means anything."""
        syns = [p for p in self._fields("tcp_lossy_ts.pcap")
                if getattr(p.transport, "flags", 0) & 0x02]
        self.assertGreaterEqual(len(syns), 2, "a SYN and a SYN-ACK")
        for syn in syns:
            self.assertIsNotNone(self._tsval(syn),
                                 "both ends should offer the option")

    def test_a_resend_carries_a_later_tsval_than_its_original(self) -> None:
        """#149's first assertion, and #90's rule in traffic packeteer did not write."""
        by_seq: dict[int, list[int]] = {}
        for pkt in self._data_segments("tcp_lossy_ts.pcap"):
            by_seq.setdefault(pkt.transport.seq, []).append(self._tsval(pkt))

        resent = {seq: vals for seq, vals in by_seq.items() if len(vals) > 1}
        self.assertTrue(resent, "the capture should hold retransmissions")
        for seq, vals in resent.items():
            with self.subTest(seq=seq):
                self.assertGreater(
                    vals[-1], vals[0],
                    "a resend is rebuilt with the clock at resend time",
                )

    def test_the_ack_answering_a_resend_echoes_the_resend(self) -> None:
        """#149's third assertion: which copy the receiver kept.

        This is the evidence a reassembler reads to decide that — the ACK
        covering a retransmitted segment echoes the TSval the *retransmission*
        carried, not the original's.
        """
        packets = self._fields("tcp_lossy_ts.pcap")
        sender = self._bulk_sender(packets)

        by_seq: dict[int, list[int]] = {}
        for index, pkt in enumerate(packets):
            if (getattr(pkt, "payload", None) and self._tsval(pkt) is not None
                    and pkt.transport.src_port == sender):
                by_seq.setdefault(pkt.transport.seq, []).append(index)
        resends = [indices[-1] for indices in by_seq.values() if len(indices) > 1]
        self.assertTrue(resends, "the capture should hold retransmissions")

        checked = 0
        for index in resends:
            resend = packets[index]
            covers = resend.transport.seq + len(resend.payload)
            for later in packets[index + 1:]:
                options = getattr(later.transport, "options", None)
                echo = getattr(options, "timestamps", None)
                if (later.transport.src_port == sender or echo is None
                        or later.transport.ack < covers):
                    continue
                with self.subTest(seq=resend.transport.seq):
                    self.assertEqual(echo[1], self._tsval(resend))
                checked += 1
                break
        self.assertTrue(checked, "no retransmission was acknowledged")

    def test_duplicate_acks_never_echo_the_out_of_order_segment(self) -> None:
        """#149's second assertion, stated as what the capture can prove.

        RFC 7323 4.3 updates `TS.Recent` only for a segment that arrives in
        order, so a duplicate ACK provoked by an out-of-order arrival echoes
        the last **in-order** segment instead.

        Naming that segment from a capture is not always possible — the
        option's clock has millisecond granularity, so segments sent inside one
        tick share a TSval and the two candidates become indistinguishable.
        What is decidable, and stronger, is the behaviour over a *run* of
        duplicate ACKs: the echo does not move, while the sender goes on
        putting newer TSvals on the wire.  A receiver updating `TS.Recent` from
        the out-of-order arrivals would echo those instead.
        """
        packets = self._fields("tcp_lossy_ts.pcap")
        sender = self._bulk_sender(packets)

        runs: list[list[tuple[int, int, int | None]]] = []
        current: list[tuple[int, int, int | None]] = []
        newest_sent: int | None = None
        for pkt in packets:
            options = getattr(pkt.transport, "options", None)
            stamps = getattr(options, "timestamps", None)
            if stamps is None:
                continue
            if pkt.transport.src_port == sender:
                newest_sent = stamps[0]
                continue
            entry = (pkt.transport.ack, stamps[1], newest_sent)
            if current and entry[0] == current[-1][0]:
                current.append(entry)
            else:
                if len(current) > 1:
                    runs.append(current)
                current = [entry]
        if len(current) > 1:
            runs.append(current)

        self.assertTrue(runs, "the capture should hold runs of duplicate ACKs")
        stale = 0
        for run in runs:
            with self.subTest(ack=run[0][0], length=len(run)):
                self.assertEqual(
                    len({echo for _, echo, _ in run}), 1,
                    "TS.Recent should not move while a hole is unfilled",
                )
            if run[-1][2] is not None and run[-1][2] > run[0][1]:
                stale += 1

        self.assertTrue(
            stale,
            "no run had a newer TSval available, so none of them proves "
            "TS.Recent was left alone rather than merely unchanged",
        )

    def test_a_duplicate_carries_the_same_tsval(self) -> None:
        """The shape the generator cannot make, which is why it is here.

        A resend and a duplicate are indistinguishable by bytes alone; the
        TSval is the whole of the difference.  These copies were made by the
        capture path, not by the sender, so theirs is identical.
        """
        seen: dict[tuple[int, int], list[int]] = {}
        for pkt in self._data_segments("tcp_dup_ts.pcap"):
            key = (pkt.transport.seq, len(pkt.payload))
            seen.setdefault(key, []).append(self._tsval(pkt))

        duplicates = {key: vals for key, vals in seen.items() if len(vals) > 1}
        self.assertTrue(duplicates, "the capture should hold duplicates")
        for key, vals in duplicates.items():
            with self.subTest(seq=key[0]):
                self.assertEqual(
                    len(set(vals)), 1,
                    "a capture-point duplicate is the same transmission twice",
                )


class TestAGapSeenByTheReceiver(_TimestampedSession):
    """What `tcp_gap_ts.pcap` and `tcp_reorder_ts.pcap` are for (#158).

    `tcp_lossy_ts.pcap` was captured at the sender, so from a reassembler's
    seat nothing in it was ever missing: every resend is a pure overlap.  These
    two were captured on the receiver's device, downstream of the impairment,
    so they hold the shape that puts real bytes behind a reorder buffer — a
    hole, the segments held out of order behind it, and the segment that
    fills it.  Between them they are the two things a late byte can be: real
    loss recovered after the gap was committed (`tcp_gap_ts`, the fill's
    TSval is **newer** than what was committed past it) or an original the
    network merely delayed (`tcp_reorder_ts`, **older**).
    """

    def test_both_ends_negotiated_timestamps(self) -> None:
        for name in ("tcp_gap_ts.pcap", "tcp_reorder_ts.pcap"):
            syns = [p for p in self._fields(name)
                    if getattr(p.transport, "flags", 0) & 0x02]
            with self.subTest(capture=name):
                self.assertGreaterEqual(len(syns), 2, "a SYN and a SYN-ACK")
                for syn in syns:
                    self.assertIsNotNone(self._tsval(syn))

    def test_the_dropped_segment_is_absent_until_its_resend(self) -> None:
        """#158's first assertion: the capture holds the gap.

        A receiver-side capture cannot hold what the router dropped, so the
        resend is the *first* time those bytes appear — unlike the sender-side
        twin, where every resend has an original in front of it.
        """
        packets, holes, fills = self._replay("tcp_gap_ts.pcap")
        self.assertTrue(holes, "the capture should hold holes")
        self.assertTrue(fills, "every hole should have been filled")
        for fill in fills:
            seq = fill["segment"].transport.seq
            with self.subTest(seq=seq):
                earlier = [p for p in packets[:fill["index"]]
                           if getattr(p, "payload", None)
                           and p.transport.seq == seq]
                self.assertFalse(earlier, "the original should not be here")

    def test_a_resend_filling_a_gap_is_newer_than_what_was_committed(self) -> None:
        """#158's second assertion, the loss branch.

        The segments held beyond the hole were sent before the resend, so a
        reassembler that has already committed them can tell a recovered loss
        from a reordering by comparing TSvals.  Segments the sender put out in
        the same 1 ms tick as the resend tie — the option's granularity — so
        the assertion is "newer than at least one, older than none".
        """
        _, _, fills = self._replay("tcp_gap_ts.pcap")
        self.assertTrue(fills)
        for fill in fills:
            tsval = self._tsval(fill["segment"])
            held = [self._tsval(pkt) for _, pkt in fill["beyond"]]
            with self.subTest(seq=fill["segment"].transport.seq):
                self.assertTrue(any(tsval > h for h in held),
                                "a resend carries the clock at resend time")
                self.assertFalse(any(tsval < h for h in held),
                                 "nothing committed past a loss is newer")

    def test_a_delayed_original_is_older_than_what_was_committed(self) -> None:
        """#158's second assertion, the reordering branch.

        The same comparison, the other way round: an original the network
        held back arrives after segments sent in later ticks, and its resend —
        the sender fast-retransmitted every one — turns up afterwards as a
        repeat with the newer clock.
        """
        packets, _, fills = self._replay("tcp_reorder_ts.pcap")
        self.assertTrue(fills)
        for fill in fills:
            segment = fill["segment"]
            tsval = self._tsval(segment)
            held = [self._tsval(pkt) for _, pkt in fill["beyond"]]
            with self.subTest(seq=segment.transport.seq):
                self.assertTrue(any(tsval < h for h in held),
                                "a delayed original predates what overtook it")
                self.assertFalse(any(tsval > h for h in held),
                                 "nothing committed past it is older")
                resends = [self._tsval(p) for p in packets[fill["index"] + 1:]
                           if getattr(p, "payload", None)
                           and p.transport.seq == segment.transport.seq]
                self.assertTrue(resends, "the sender should have resent it")
                self.assertGreater(min(resends), tsval,
                                   "the spurious resend carries a later clock")

    def test_the_ack_answering_a_fill_echoes_the_fill(self) -> None:
        """#158's third assertion, from the receiver's own stack.

        RFC 7323 4.3: the segment that advances the left edge updates
        `TS.Recent`, so the ACK covering a fill echoes the fill's TSval, in
        both files — whichever of the two causes put it there.
        """
        for name in ("tcp_gap_ts.pcap", "tcp_reorder_ts.pcap"):
            packets, _, fills = self._replay(name)
            sender = self._bulk_sender(packets)
            for fill in fills:
                segment = fill["segment"]
                ack = self._covering_ack(packets, fill["index"], sender)
                with self.subTest(capture=name, seq=segment.transport.seq):
                    self.assertIsNotNone(ack, "a fill was never acknowledged")
                    self.assertEqual(ack.transport.options.timestamps[1],
                                     self._tsval(segment))

    def test_the_receiver_duplicate_acks_while_the_hole_is_open(self) -> None:
        """The dup-ACK run is the receiver's, since the capture is on its device."""
        for name in ("tcp_gap_ts.pcap", "tcp_reorder_ts.pcap"):
            packets, holes, _ = self._replay(name)
            sender = self._bulk_sender(packets)
            for hole in holes:
                with self.subTest(capture=name, start=hole["start"]):
                    self.assertIn("filled", hole)
                    dup_acks = [
                        p for p in packets[hole["opened"]:hole["filled"]]
                        if p.transport.src_port != sender
                        and not getattr(p, "payload", None)
                        and p.transport.ack == hole["start"]
                    ]
                    self.assertTrue(dup_acks, "the receiver should have asked")


class TestACorruptedSegmentAndItsResend(_TimestampedSession):
    """What `tcp_corrupt_ts.pcap` is for (#160).

    Every other resend in the corpus is byte-identical to its original, as a
    resend is unless one copy was damaged in flight.  Here the loss is
    corruption: `netem corrupt` on the router, captured on the receiver with
    checksum offload off, so the damaged copy is in the file with a checksum
    that fails, the receiver drops it, and the clean resend follows.  Two
    copies of one range that genuinely differ, and a checksum failure that
    means what it says.
    """

    def _corruptions(self) -> tuple[list, int, list[tuple[int, int]]]:
        """Return the packets, the sender, and (damaged, resend) index pairs."""
        packets = self._fields("tcp_corrupt_ts.pcap")
        sender = self._bulk_sender(packets)
        pairs = []
        for index, pkt in enumerate(packets):
            if (pkt.transport.src_port != sender or pkt.transport.checksum is None
                    or not getattr(pkt, "payload", None)):
                continue
            resend = next(
                (later for later, p in enumerate(packets[index + 1:], index + 1)
                 if getattr(p, "payload", None) and p.transport.seq == pkt.transport.seq
                 and p.transport.checksum is None),
                None,
            )
            self.assertIsNotNone(resend, f"frame {index + 1} was never resent clean")
            pairs.append((index, resend))
        self.assertTrue(pairs, "the capture should hold corrupted segments")
        return packets, sender, pairs

    def test_only_the_damaged_copies_fail_their_checksum(self) -> None:
        """The failure has to mean something, so the rest must verify.

        A recorded `transport.checksum` after parsing is one that was wrong
        on the wire.  On every other TCP capture here that is all of them,
        for the offload reason the manifest gives; on this one it is exactly
        the damaged copies, and every one of them is later resent.
        """
        packets, sender, pairs = self._corruptions()
        wrong = [i for i, p in enumerate(packets) if p.transport.checksum is not None]
        self.assertEqual(sorted(wrong), sorted(damaged for damaged, _ in pairs))
        self.assertLess(len(wrong), len(packets) // 2, "offload noise")

    def test_the_damaged_copy_and_its_resend_differ_in_payload(self) -> None:
        """#160's first two assertions: the one shape where two copies disagree.

        netem flips one bit, so the copies differ in exactly one byte by one
        bit — and the resend, being rebuilt, carries a later TSval.
        """
        packets, _, pairs = self._corruptions()
        for damaged, resend in pairs:
            a, b = packets[damaged], packets[resend]
            with self.subTest(seq=a.transport.seq):
                self.assertEqual(len(a.payload), len(b.payload))
                diff = [i for i, (x, y) in enumerate(zip(a.payload, b.payload, strict=True))
                        if x != y]
                self.assertEqual(len(diff), 1, "one byte differs")
                self.assertEqual(
                    bin(a.payload[diff[0]] ^ b.payload[diff[0]]).count("1"), 1,
                    "by one bit",
                )
                self.assertGreater(self._tsval(b), self._tsval(a))

    def test_the_ack_covering_the_clean_resend_echoes_it(self) -> None:
        """#160's third assertion: which copy the receiver kept.

        The evidence a reassembler preferring the acknowledged copy reads,
        and evidence that is independent of the checksum.  Only a resend
        that arrived in order advanced the left edge, so only those are
        asked; one that arrived behind another hole is covered by the ACK
        answering whatever filled that hole.
        """
        packets, sender, pairs = self._corruptions()
        _, _, fills = self._replay("tcp_corrupt_ts.pcap", honour_checksums=True)
        in_order = {fill["index"] for fill in fills}
        checked = 0
        for _, resend in pairs:
            if resend not in in_order:
                continue
            ack = self._covering_ack(packets, resend, sender)
            with self.subTest(seq=packets[resend].transport.seq):
                self.assertIsNotNone(ack)
                self.assertEqual(ack.transport.options.timestamps[1],
                                 self._tsval(packets[resend]))
            checked += 1
        self.assertTrue(checked, "no clean resend arrived in order")

    def test_the_damaged_copy_opened_no_hole(self) -> None:
        """From the receiver's seat a corrupted segment never arrived at all.

        Replayed honouring checksums, the damaged copies vanish and each
        leaves a hole that its resend fills with a newer TSval — the same
        shape as `tcp_gap_ts.pcap`, reached by a different kind of loss.
        """
        _, holes, fills = self._replay("tcp_corrupt_ts.pcap", honour_checksums=True)
        self.assertTrue(holes)
        for fill in fills:
            held = [self._tsval(pkt) for _, pkt in fill["beyond"]]
            with self.subTest(seq=fill["segment"].transport.seq):
                self.assertTrue(any(self._tsval(fill["segment"]) > h for h in held))
                self.assertFalse(any(self._tsval(fill["segment"]) < h for h in held))


class TestASessionThatWrapsThroughTwoToThe32(_TimestampedSession):
    """What `tcp_wrap_ts.pcap` is for (#161).

    A reassembler compares sequence numbers with serial arithmetic, which is
    undefined for two numbers 2**31 apart, and RFC 7323's answer is that a
    segment's TSval is a monotonic clock its sequence number is not.  No
    other capture, real or generated, wraps.  This one was collected with the
    last 2 KiB before the wrap on a slow path, so it also holds the case
    where sequence number and TSval disagree about order and the TSval is
    right.
    """

    _NAME = "tcp_wrap_ts.pcap"

    def _isn(self, packets: list) -> int:
        synack = next(p for p in packets if p.transport.flags & 0x12 == 0x12)
        return synack.transport.seq

    def test_the_sequence_numbers_wrap(self) -> None:
        """#161's first assertion.

        The server's ISN sits inside the transfer below 2**32, so the data
        carries numbers just below it and then small ones — and every
        post-wrap segment carries a TSval no older than any pre-wrap
        original's, which is what places them for a reader of the option.
        Resends of pre-wrap bytes are sent after the wrap and are excluded:
        their clock is the disagreement the third assertion is about.
        """
        packets, _, _ = self._replay(self._NAME)
        sender = self._bulk_sender(packets)
        isn = self._isn(packets)
        data = [p for p in packets if getattr(p, "payload", None)
                and p.transport.src_port == sender]
        sent = sum(len(p.payload) for p in {p.transport.seq: p for p in data}.values())
        self.assertLess((1 << 32) - isn, sent, "the ISN is inside the transfer")

        pre = [p for p in data if p.transport.seq >= (1 << 31)]
        post = [p for p in data if p.transport.seq < (1 << 31)]
        self.assertTrue(pre and post, "segments on both sides of the wrap")
        originals: dict[int, object] = {}
        for p in pre:
            originals.setdefault(p.transport.seq, p)
        newest_pre = max(self._tsval(p) for p in originals.values())
        for p in post:
            with self.subTest(seq=p.transport.seq):
                self.assertGreaterEqual(self._tsval(p), newest_pre)

    def test_the_receivers_acks_wrap_with_them(self) -> None:
        """#161's second assertion, from the receiver's own stack."""
        packets = self._fields(self._NAME)
        sender = self._bulk_sender(packets)
        acks = [p for p in packets if p.transport.src_port != sender
                and not p.transport.flags & 0x02]
        numbers = [p.transport.ack for p in acks]
        self.assertTrue(any(n >= (1 << 31) for n in numbers))
        self.assertTrue(any(n < (1 << 31) for n in numbers))
        echoes = [p.transport.options.timestamps[1] for p in acks
                  if getattr(p.transport.options, "timestamps", None)]
        self.assertGreater(len(echoes), 1)
        for earlier, later in zip(echoes, echoes[1:], strict=False):
            self.assertLessEqual(earlier, later, "TSecr keeps advancing")

    def test_an_original_from_before_the_wrap_arrives_after_segments_from_after_it(self) -> None:
        """#161's third assertion: the one case where only the TSval is right.

        Numerically the delayed original is *larger* than every segment held
        beyond it; serially it is before them; its TSval is older than all of
        theirs.  A reader that trusts the sequence number half-space here
        drops new bytes as old.
        """
        _, _, fills = self._replay(self._NAME)
        crossing = [f for f in fills if f["segment"].transport.seq >= (1 << 31)
                    and any(pkt.transport.seq < (1 << 31) for _, pkt in f["beyond"])]
        self.assertTrue(crossing, "an original from below 2**32 should arrive late")
        for fill in crossing:
            tsval = self._tsval(fill["segment"])
            with self.subTest(seq=fill["segment"].transport.seq):
                for _, held in fill["beyond"]:
                    self.assertGreater(fill["segment"].transport.seq, held.transport.seq)
                    self.assertTrue(self._after(held.transport.seq, fill["segment"].transport.seq))
                    self.assertLess(tsval, self._tsval(held))


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
                        for depth, value in _every_address(pkt):
                            address = ipaddress.ip_address(value)
                            with self.subTest(capture=path.name, packet=index,
                                              address=value, depth=depth):
                                self.assertFalse(
                                    address.is_global,
                                    "a routable address survived sanitisation",
                                )

    def test_the_scan_reaches_inside_a_tunnel(self) -> None:
        """#151: reading `pkt.ip` alone guards the wrong header.

        On a tunnelled packet `pkt.ip` is the *outer* header, so the sweep
        above passed a file whose inner addresses were untouched — which is
        precisely how a VXLAN capture could have been committed with real
        addresses in it and every check green.
        """
        from packeteer.generate import PacketBuilder
        from packeteer.parse import parse_packet

        raw = (PacketBuilder()
               .ethernet().ip(src="192.0.2.1", dst="192.0.2.2")
               .udp(dst_port=4789).vxlan(vni=7)
               .ethernet().ip(src="8.8.8.8", dst="1.1.1.1")
               .tcp(dst_port=80).build())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            pkt = parse_packet(raw)

        found = {value for _, value in _every_address(pkt)}
        self.assertIn("192.0.2.1", found, "the outer header is still scanned")
        self.assertIn("8.8.8.8", found,
                      "the scan must follow the tunnel, or it guards nothing")


if __name__ == "__main__":
    unittest.main()
