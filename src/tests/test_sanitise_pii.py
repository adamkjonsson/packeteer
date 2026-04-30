from __future__ import annotations

import io
import json
import unittest
import warnings
from typing import Any

from packeteer.generate import PacketBuilder
from packeteer.parse import parse_pcap_file
from packeteer.pcap import write_pcap
from packeteer.sanitise import (
    PersonalDataWarning,
    SanitiseOptions,
    _excerpt,
    _scan_emails,
    _scan_names,
    sanitise,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _spec(*payloads: str) -> dict:
    """Build a minimal packet spec with UTF-8 encoded payloads."""
    packets = []
    for i, text in enumerate(payloads, 1):
        packets.append({
            "network": {"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "tcp", "ttl": 64},
            "transport": {"src_port": 1234, "dst_port": 80, "seq": 0, "ack": 0,
                          "flags": 2, "window": 65535},
            "payload": {"data": text, "encoding": "utf8"},
            "packet_metadata": {"packet_num": i, "timestamp_s": 0, "timestamp_us": 0},
        })
    return {"packets": packets}


def _pii_warnings(spec: dict, **opts_kwargs: Any) -> list[warnings.WarningMessage]:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        sanitise(spec, SanitiseOptions(scan_pii=True, **opts_kwargs))
    return [w for w in caught if issubclass(w.category, PersonalDataWarning)]


# ── PersonalDataWarning class ─────────────────────────────────────────────────

class TestPersonalDataWarning(unittest.TestCase):
    def test_attributes(self) -> None:
        w = PersonalDataWarning("msg", kind="email", match="ctx", text="a@b.com", packet_num=3)
        self.assertEqual(w.kind, "email")
        self.assertEqual(w.match, "ctx")
        self.assertEqual(w.text, "a@b.com")
        self.assertEqual(w.packet_num, 3)
        self.assertIsInstance(w, UserWarning)

    def test_name_kind(self) -> None:
        w = PersonalDataWarning("msg", kind="name", match="ctx", text="Alice Smith", packet_num=1)
        self.assertEqual(w.kind, "name")


# ── _excerpt ──────────────────────────────────────────────────────────────────

class TestExcerpt(unittest.TestCase):
    def test_short_text_no_ellipsis(self) -> None:
        result = _excerpt("hello@world.com", 0, 15)
        self.assertEqual(result, "hello@world.com")
        self.assertNotIn("…", result)

    def test_prefix_ellipsis_when_left_truncated(self) -> None:
        text = "x" * 50 + "email@test.com" + "y" * 5
        result = _excerpt(text, 50, 64)
        self.assertTrue(result.startswith("…"))

    def test_suffix_ellipsis_when_right_truncated(self) -> None:
        text = "x" * 5 + "email@test.com" + "y" * 50
        result = _excerpt(text, 5, 19)
        self.assertTrue(result.endswith("…"))

    def test_match_present_in_excerpt(self) -> None:
        text = "Contact alice@example.com for help"
        start = text.index("alice")
        result = _excerpt(text, start, start + len("alice@example.com"))
        self.assertIn("alice@example.com", result)

    def test_context_chars_included(self) -> None:
        text = "prefix " + "a@b.com" + " suffix"
        start = text.index("a@b.com")
        result = _excerpt(text, start, start + 7)
        self.assertIn("prefix", result)
        self.assertIn("suffix", result)


# ── _scan_emails ──────────────────────────────────────────────────────────────

class TestScanEmails(unittest.TestCase):
    def test_finds_single_email(self) -> None:
        matches = _scan_emails("Contact alice@example.com for info")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "alice@example.com")

    def test_no_email_returns_empty(self) -> None:
        self.assertEqual(_scan_emails("Hello world, no address here"), [])

    def test_finds_multiple_emails(self) -> None:
        matches = _scan_emails("alice@ex.com and bob@ex.com")
        texts = [m[0] for m in matches]
        self.assertIn("alice@ex.com", texts)
        self.assertIn("bob@ex.com", texts)

    def test_start_end_positions_correct(self) -> None:
        text = "send to alice@example.com please"
        matches = _scan_emails(text)
        self.assertEqual(len(matches), 1)
        email, start, end = matches[0]
        self.assertEqual(text[start:end], email)


# ── _scan_names ───────────────────────────────────────────────────────────────

class TestScanNames(unittest.TestCase):
    def test_tier1_quoted_display_name(self) -> None:
        matches = _scan_names('"Alice Smith" <alice@example.com>')
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Alice Smith")

    def test_tier1_unquoted_display_name(self) -> None:
        matches = _scan_names("Alice Smith <alice@example.com>")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Alice Smith")

    def test_tier1_bare_email_no_name(self) -> None:
        matches = _scan_names("<alice@example.com>")
        self.assertEqual(matches, [])

    def test_tier1_three_word_name(self) -> None:
        matches = _scan_names("Mary Jane Watson <mj@avengers.org>")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Mary Jane Watson")

    def test_tier2_name_label(self) -> None:
        matches = _scan_names("name: Bob Jones")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Bob Jones")

    def test_tier2_recipient_label(self) -> None:
        matches = _scan_names("recipient: Jane Doe")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Jane Doe")

    def test_tier2_from_label(self) -> None:
        matches = _scan_names("From: Alice Smith")
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0][0], "Alice Smith")

    def test_tier2_single_word_not_flagged(self) -> None:
        # Single title-case word after label is not a name
        self.assertEqual(_scan_names("user: alice"), [])

    def test_tier2_unrecognised_label_not_flagged(self) -> None:
        self.assertEqual(_scan_names("host: Main Street"), [])

    def test_positions_correct(self) -> None:
        text = "name: Bob Jones and more"
        matches = _scan_names(text)
        self.assertEqual(len(matches), 1)
        name, start, end = matches[0]
        self.assertEqual(text[start:end], name)


# ── scan_pii=False: no warnings ───────────────────────────────────────────────

class TestScanPiiDisabled(unittest.TestCase):
    def test_no_warnings_by_default(self) -> None:
        spec = _spec("Hello alice@example.com")
        # scan_pii is True in _pii_warnings — but test the default
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            sanitise(spec)  # default SanitiseOptions — scan_pii=False
        pii_default = [w for w in caught if issubclass(w.category, PersonalDataWarning)]
        self.assertEqual(pii_default, [])

    def test_hex_payload_not_scanned(self) -> None:
        # "alice@example.com" encoded as hex — must not be scanned
        hex_data = "alice@example.com".encode().hex()
        spec = {"packets": [{
            "payload": {"data": hex_data},
            "packet_metadata": {"packet_num": 1, "timestamp_s": 0, "timestamp_us": 0},
        }]}
        pii = _pii_warnings(spec)
        self.assertEqual(pii, [])


# ── Email detection via sanitise() ────────────────────────────────────────────

class TestEmailDetection(unittest.TestCase):
    def test_email_in_utf8_payload_warns(self) -> None:
        pii = _pii_warnings(_spec("Hello alice@example.com"))
        self.assertEqual(len(pii), 1)
        w = pii[0].message
        assert isinstance(w, PersonalDataWarning)
        self.assertEqual(w.kind, "email")
        self.assertEqual(w.text, "alice@example.com")
        self.assertEqual(w.packet_num, 1)

    def test_excerpt_in_match(self) -> None:
        pii = _pii_warnings(_spec("Contact: alice@example.com — Sales"))
        w = pii[0].message
        assert isinstance(w, PersonalDataWarning)
        self.assertIn("alice@example.com", w.match)
        self.assertIn("Contact", w.match)

    def test_no_warning_for_no_email(self) -> None:
        self.assertEqual(_pii_warnings(_spec("Hello world, no email here")), [])

    def test_duplicate_email_in_same_payload_warned_once(self) -> None:
        pii = _pii_warnings(_spec("alice@ex.com and again alice@ex.com"))
        email_warnings = [w for w in pii if w.message.kind == "email"]
        self.assertEqual(len(email_warnings), 1)


# ── Name detection via sanitise() ────────────────────────────────────────────

class TestNameDetection(unittest.TestCase):
    def test_display_name_warns(self) -> None:
        pii = _pii_warnings(_spec('"Alice Smith" <alice@example.com>'))
        kinds = {w.message.kind for w in pii}
        self.assertIn("name", kinds)
        name_w = next(w.message for w in pii if w.message.kind == "name")
        self.assertEqual(name_w.text, "Alice Smith")

    def test_display_name_also_triggers_email_warning(self) -> None:
        pii = _pii_warnings(_spec('"Alice Smith" <alice@example.com>'))
        kinds = {w.message.kind for w in pii}
        self.assertEqual(kinds, {"email", "name"})

    def test_field_label_name_warns(self) -> None:
        pii = _pii_warnings(_spec("name: Bob Jones\nsome other data"))
        name_ws = [w for w in pii if w.message.kind == "name"]
        self.assertEqual(len(name_ws), 1)
        self.assertEqual(name_ws[0].message.text, "Bob Jones")

    def test_single_word_after_label_no_warning(self) -> None:
        pii = _pii_warnings(_spec("user: alice"))
        self.assertEqual(pii, [])


# ── Consolidation ─────────────────────────────────────────────────────────────

class TestConsolidation(unittest.TestCase):
    def test_same_email_in_multiple_packets_consolidated(self) -> None:
        spec = _spec("alice@example.com", "nothing here", "alice@example.com again")
        pii = _pii_warnings(spec)
        email_ws = [w for w in pii if w.message.kind == "email"]
        self.assertEqual(len(email_ws), 1)
        msg = email_ws[0].message.args[0]
        self.assertIn("2 packets", msg)
        # packet_num 1 and 3 must appear
        self.assertIn("1", msg)
        self.assertIn("3", msg)

    def test_different_emails_separate_warnings(self) -> None:
        pii = _pii_warnings(_spec("alice@ex.com", "bob@ex.com"))
        email_ws = [w for w in pii if w.message.kind == "email"]
        self.assertEqual(len(email_ws), 2)

    def test_consolidated_warning_packet_num_attribute(self) -> None:
        spec = _spec("alice@example.com", "alice@example.com")
        pii = _pii_warnings(spec)
        w = pii[0].message
        assert isinstance(w, PersonalDataWarning)
        self.assertEqual(w.packet_num, 1)   # first occurrence

    def test_single_packet_singular_count(self) -> None:
        pii = _pii_warnings(_spec("alice@example.com"))
        msg = pii[0].message.args[0]
        self.assertIn("1 packet", msg)
        self.assertNotIn("packets", msg.split("1 packet")[1][:1])


# ── packet_num in packet_metadata ────────────────────────────────────────────

class TestPacketNumInMetadata(unittest.TestCase):
    def _make_pcap_bytes(self, n: int) -> bytes:
        buf = io.BytesIO()
        pkts = [
            PacketBuilder()
            .ethernet()
            .ip(src="10.0.0.1", dst="10.0.0.2")
            .tcp(dst_port=80)
            .build()
            for _ in range(n)
        ]
        write_pcap([(p, i, 0) for i, p in enumerate(pkts)], file_object=buf)
        buf.seek(0)
        return buf.read()

    def test_packet_num_1_based(self) -> None:
        raw = self._make_pcap_bytes(3)
        result = json.loads(parse_pcap_file(file_object=io.BytesIO(raw)))
        for i, pkt in enumerate(result["packets"], 1):
            self.assertEqual(pkt["packet_metadata"]["packet_num"], i)

    def test_single_packet_has_num_1(self) -> None:
        raw = self._make_pcap_bytes(1)
        result = json.loads(parse_pcap_file(file_object=io.BytesIO(raw)))
        self.assertEqual(result["packets"][0]["packet_metadata"]["packet_num"], 1)
