"""The pcap writers take any iterable, consumed once, in order (#204).

`write_pcap` and `write_pcapng` were annotated and documented as taking a
list, though they only ever looped over it once.  A caller exporting a file
larger than memory, one record at a time, could not rely on that.  It is a
contract now, and a writer needs exactly one destination, as a reader does:
writing to two drew the records twice, and a generator's second pass was
empty.
"""
from __future__ import annotations

import io
import tempfile
import unittest
from collections.abc import Callable, Iterator
from pathlib import Path

from packeteer.pcap import LINKTYPE_RAW, read_pcap, write_pcap, write_pcapng

_WRITERS: dict[str, Callable[..., None]] = {"pcap": write_pcap, "pcapng": write_pcapng}


def _records(count: int) -> list[tuple[bytes, int, int]]:
    return [(b"\x45" + bytes(19) + bytes([i]), 1_700_000_000 + i, i) for i in range(count)]


class _Once:
    """An iterable of records that refuses a second pass and counts its draws."""

    def __init__(self, records: list[tuple[bytes, int, int]],
                 check: Callable[[int], None] | None = None) -> None:
        self.records = records
        self.check = check
        self.drawn = 0
        self.passes = 0

    def __iter__(self) -> Iterator[tuple[bytes, int, int]]:
        self.passes += 1
        if self.passes > 1:
            raise AssertionError("the records were drawn a second time")
        for record in self.records:
            if self.check is not None:
                self.check(self.drawn)
            self.drawn += 1
            yield record


class TestAGeneratorIsWritten(unittest.TestCase):

    def test_to_a_file_object_and_to_a_path(self) -> None:
        records = _records(5)
        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind, to="file_object"):
                buf = io.BytesIO()
                write((r for r in records), file_object=buf, link_type=LINKTYPE_RAW)
                buf.seek(0)
                self.assertEqual([tuple(r)[:3] for r in read_pcap(file_object=buf).packets],
                                 records)
            with self.subTest(writer=kind, to="path"), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / f"out.{kind}"
                write((r for r in records), path=path, link_type=LINKTYPE_RAW)
                self.assertEqual([tuple(r)[:3] for r in read_pcap(path=path).packets],
                                 records)

    def test_each_record_is_drawn_once(self) -> None:
        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind):
                once = _Once(_records(7))
                write(once, file_object=io.BytesIO(), link_type=LINKTYPE_RAW)
                self.assertEqual((once.passes, once.drawn), (1, 7))

    def test_each_record_is_written_before_the_next_is_drawn(self) -> None:
        """Streaming, shown without a capture larger than memory.

        As each record is drawn, the destination must already hold every
        record before it: a writer that collected them first would fail.
        """
        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind):
                buf = io.BytesIO()
                sizes: list[int] = []

                def check(drawn: int, buf: io.BytesIO = buf, sizes: list[int] = sizes) -> None:
                    sizes.append(len(buf.getvalue()))
                    if drawn:
                        self.assertGreater(sizes[-1], sizes[-2])

                write(_Once(_records(4), check), file_object=buf, link_type=LINKTYPE_RAW)
                self.assertEqual(len(sizes), 4)

    def test_a_failure_partway_leaves_the_records_before_it(self) -> None:
        def broken() -> Iterator[tuple[bytes, int, int]]:
            yield from _records(2)
            raise RuntimeError("the source ran dry")

        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind):
                buf = io.BytesIO()
                with self.assertRaises(RuntimeError):
                    write(broken(), file_object=buf, link_type=LINKTYPE_RAW)
                buf.seek(0)
                self.assertEqual(len(read_pcap(file_object=buf).packets), 2)


class TestExactlyOneDestination(unittest.TestCase):
    """As for the readers: both drew the records twice, and neither wrote nothing."""

    def test_both_are_refused(self) -> None:
        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "out"
                with self.assertRaisesRegex(ValueError, "exactly one of 'path' or 'file_object'"):
                    write(_records(1), path=path, file_object=io.BytesIO())
                self.assertFalse(path.exists(), "nothing is written when refused")

    def test_neither_is_refused(self) -> None:
        for kind, write in _WRITERS.items():
            with self.subTest(writer=kind), \
                    self.assertRaisesRegex(ValueError, "exactly one of 'path' or 'file_object'"):
                write(_records(1))


if __name__ == "__main__":
    unittest.main()
