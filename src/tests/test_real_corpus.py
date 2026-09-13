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


class TestALossyTimestampedSession(unittest.TestCase):
    """What `tcp_lossy_ts.pcap` and `tcp_dup_ts.pcap` are for (#149).

    #90 made every generated resend carry a fresh clock, which is what lets an
    analyser tell a retransmission from a duplicate.  Nothing said a real stack
    does the same: the corpus's one complete session, `tcp_v4.pcapng`, loses
    nothing, and every capture that repeats a segment predates the option.
    These two files are that evidence, and each test below is one of the three
    properties #149 named.
    """

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
