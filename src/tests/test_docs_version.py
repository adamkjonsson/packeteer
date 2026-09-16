"""The documentation's transcripts name the version being released.

Three sweeps in a row — 0.13.0, 0.15.0 and 0.16.0 — found generated-output
transcripts in `docs/` still naming the previous release.  A transcript is a
claim about what the tool prints, so a stale one is wrong documentation, and
the sweep is the wrong place to notice: this fails the moment
`pyproject.toml` moves to the next version, at the start of a cycle, and
stays red until the transcripts follow.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_DOCS = _ROOT / "docs"

#: A version as a transcript prints it: ``packeteer 0.16.0``.  Prose says
#: ``0.16.0`` bare or in a ``versionchanged`` directive, and that is history
#: rather than a claim about the current output, so it is not matched.
_TRANSCRIPT = re.compile(r"\bpacketeer (\d+\.\d+\.\d+)\b")


def _base_version() -> str:
    """Return the version in ``pyproject.toml`` without any ``.devN`` suffix."""
    text = (_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    version = re.search(r'^version = "([^"]+)"', text, re.MULTILINE).group(1)
    return version.split(".dev")[0]


class TestTranscriptsNameTheCurrentVersion(unittest.TestCase):

    def test_every_transcript_matches_pyproject(self) -> None:
        expected = _base_version()
        found = 0
        for page in sorted(_DOCS.rglob("*.md")):
            if "_build" in page.parts:
                continue
            for line_no, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
                for match in _TRANSCRIPT.finditer(line):
                    found += 1
                    with self.subTest(page=str(page.relative_to(_ROOT)), line=line_no):
                        self.assertEqual(match.group(1), expected,
                                         "a transcript names a version that is not this one")
        self.assertTrue(found, "the docs carry transcripts; the pattern should find them")
