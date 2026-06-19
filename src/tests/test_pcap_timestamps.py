"""Tests for the datetime <-> pcap timestamp converters."""
from __future__ import annotations

import io
import unittest
from datetime import datetime, timedelta, timezone

from packeteer.pcap import (
    datetime_to_pcap_ts,
    pcap_ts_to_datetime,
    read_pcap,
    write_pcap,
)


class TestDatetimeToPcapTs(unittest.TestCase):
    def test_epoch(self):
        self.assertEqual(
            datetime_to_pcap_ts(datetime(1970, 1, 1, tzinfo=timezone.utc)),
            (0, 0),
        )

    def test_known_value_with_microseconds(self):
        dt = datetime(2021, 1, 1, 0, 0, 0, 500_000, tzinfo=timezone.utc)
        sec, frac = datetime_to_pcap_ts(dt)
        self.assertEqual(sec, 1609459200)
        self.assertEqual(frac, 500_000)

    def test_naive_treated_as_utc(self):
        naive = datetime(2021, 1, 1, 0, 0, 0)
        aware = datetime(2021, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        self.assertEqual(datetime_to_pcap_ts(naive), datetime_to_pcap_ts(aware))

    def test_aware_offset_converted_to_utc(self):
        # 01:00 at +01:00 is the same instant as 00:00 UTC.
        plus_one = datetime(2021, 1, 1, 1, 0, 0, tzinfo=timezone(timedelta(hours=1)))
        self.assertEqual(datetime_to_pcap_ts(plus_one), (1609459200, 0))

    def test_nanoseconds_scaling(self):
        dt = datetime(1970, 1, 1, 0, 0, 0, 123_456, tzinfo=timezone.utc)
        self.assertEqual(datetime_to_pcap_ts(dt, nanoseconds=True), (0, 123_456_000))

    def test_microsecond_exact_no_float_drift(self):
        # 0.1s is not exactly representable in binary float; integer math must
        # still yield exactly 100000 microseconds.
        dt = datetime(2000, 6, 15, 12, 0, 0, 100_000, tzinfo=timezone.utc)
        _, frac = datetime_to_pcap_ts(dt)
        self.assertEqual(frac, 100_000)

    def test_pre_epoch_raises(self):
        with self.assertRaises(ValueError):
            datetime_to_pcap_ts(datetime(1969, 12, 31, 23, 59, 59, tzinfo=timezone.utc))

    def test_beyond_2106_raises(self):
        with self.assertRaises(ValueError):
            datetime_to_pcap_ts(datetime(2200, 1, 1, tzinfo=timezone.utc))


class TestPcapTsToDatetime(unittest.TestCase):
    def test_epoch(self):
        self.assertEqual(
            pcap_ts_to_datetime(0, 0),
            datetime(1970, 1, 1, tzinfo=timezone.utc),
        )

    def test_returns_aware_utc(self):
        dt = pcap_ts_to_datetime(1609459200, 500_000)
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt, datetime(2021, 1, 1, 0, 0, 0, 500_000, tzinfo=timezone.utc))

    def test_nanoseconds_truncated_to_microseconds(self):
        dt = pcap_ts_to_datetime(0, 123_456_789, nanoseconds=True)
        self.assertEqual(dt.microsecond, 123_456)   # 789 ns dropped

    def test_round_trip_microseconds(self):
        original = datetime(2023, 3, 14, 15, 9, 26, 535_897, tzinfo=timezone.utc)
        self.assertEqual(
            pcap_ts_to_datetime(*datetime_to_pcap_ts(original)),
            original,
        )

    def test_round_trip_nanoseconds_microsecond_grid(self):
        original = datetime(2023, 3, 14, 15, 9, 26, 535_897, tzinfo=timezone.utc)
        sec, frac = datetime_to_pcap_ts(original, nanoseconds=True)
        self.assertEqual(
            pcap_ts_to_datetime(sec, frac, nanoseconds=True),
            original,
        )


class TestConverterWithWriter(unittest.TestCase):
    def test_datetime_timestamp_written_and_read_back(self):
        dt = datetime(2021, 1, 1, 0, 0, 0, 250_000, tzinfo=timezone.utc)
        buf = io.BytesIO()
        write_pcap([(b"\x00" * 14, *datetime_to_pcap_ts(dt))], file_object=buf)
        buf.seek(0)
        pcap = read_pcap(file_object=buf)
        _, ts_sec, ts_frac = pcap.packets[0]
        self.assertEqual(
            pcap_ts_to_datetime(ts_sec, ts_frac, nanoseconds=pcap.header.nanoseconds),
            dt,
        )


if __name__ == "__main__":
    unittest.main()
