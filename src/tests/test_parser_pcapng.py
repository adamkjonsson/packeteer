"""Tests for pcapng reading via read_pcap (auto-detect) and roundtrip with write_pcapng."""
import io
import struct
import unittest

from packeteer.pcap import write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW
from packeteer.pcap import read_pcap, PcapFile, PcapFileHeader


def _write(packets, **kwargs) -> io.BytesIO:
    buf = io.BytesIO()
    write_pcapng(packets, file_object=buf, **kwargs)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Auto-detect: pcapng files are accepted by read_pcap
# ---------------------------------------------------------------------------

class TestReadPcapngAutoDetect(unittest.TestCase):
    def test_returns_pcap_file_instance(self):
        result = read_pcap(file_object=_write([(b"\x00" * 10, 0, 0)]))
        self.assertIsInstance(result, PcapFile)

    def test_returns_pcap_file_header_instance(self):
        result = read_pcap(file_object=_write([(b"\x00" * 10, 0, 0)]))
        self.assertIsInstance(result.header, PcapFileHeader)

    def test_pcap_files_still_work_after_auto_detect(self):
        from packeteer.pcap import write_pcap
        buf = io.BytesIO()
        write_pcap([(b"\xaa" * 10, 42, 100)], file_object=buf)
        buf.seek(0)
        result = read_pcap(file_object=buf)
        self.assertEqual(result.packets[0][0], b"\xaa" * 10)


# ---------------------------------------------------------------------------
# File header fields
# ---------------------------------------------------------------------------

class TestReadPcapngHeader(unittest.TestCase):
    def _header(self, **kwargs) -> PcapFileHeader:
        return read_pcap(file_object=_write([(b"\x00" * 10, 0, 0)], **kwargs)).header

    def test_link_type_ethernet(self):
        self.assertEqual(self._header(link_type=LINKTYPE_ETHERNET).link_type, LINKTYPE_ETHERNET)

    def test_link_type_raw(self):
        self.assertEqual(self._header(link_type=LINKTYPE_RAW).link_type, LINKTYPE_RAW)

    def test_nanoseconds_false_for_usec(self):
        self.assertFalse(self._header(nanoseconds=False).nanoseconds)

    def test_nanoseconds_true_for_nsec(self):
        self.assertTrue(self._header(nanoseconds=True).nanoseconds)

    def test_snaplen(self):
        self.assertEqual(self._header().snaplen, 65535)

    def test_version_major(self):
        self.assertEqual(self._header().version_major, 1)

    def test_version_minor(self):
        self.assertEqual(self._header().version_minor, 0)


# ---------------------------------------------------------------------------
# Packet data and timestamps
# ---------------------------------------------------------------------------

class TestReadPcapngPackets(unittest.TestCase):
    def test_empty_file_returns_no_packets(self):
        result = read_pcap(file_object=_write([]))
        self.assertEqual(result.packets, [])

    def test_single_packet_count(self):
        result = read_pcap(file_object=_write([(b"\x00" * 10, 0, 0)]))
        self.assertEqual(len(result.packets), 1)

    def test_single_packet_data(self):
        payload = b"\xde\xad\xbe\xef" * 4
        result = read_pcap(file_object=_write([(payload, 0, 0)]))
        self.assertEqual(result.packets[0][0], payload)

    def test_multiple_packets_count(self):
        pkts = [(bytes([i] * 10), 0, i) for i in range(6)]
        result = read_pcap(file_object=_write(pkts))
        self.assertEqual(len(result.packets), 6)

    def test_multiple_packets_data_preserved(self):
        pkts = [(bytes([i] * 10), 0, i) for i in range(5)]
        result = read_pcap(file_object=_write(pkts))
        for i, (data, _, _) in enumerate(result.packets):
            self.assertEqual(data, bytes([i] * 10))

    def test_timestamp_seconds(self):
        result = read_pcap(file_object=_write([(b"\x00" * 8, 1700000000, 0)]))
        self.assertEqual(result.packets[0][1], 1700000000)

    def test_timestamp_microseconds(self):
        result = read_pcap(file_object=_write([(b"\x00" * 8, 0, 500000)]))
        self.assertEqual(result.packets[0][2], 500000)

    def test_timestamp_nanoseconds(self):
        result = read_pcap(file_object=_write([(b"\x00" * 8, 0, 999_999_999)], nanoseconds=True))
        self.assertEqual(result.packets[0][2], 999_999_999)

    def test_timestamp_order_preserved(self):
        pkts = [(b"\x00" * 4, 1000 + i, i * 1000) for i in range(4)]
        result = read_pcap(file_object=_write(pkts))
        for i, (_, ts_sec, ts_frac) in enumerate(result.packets):
            self.assertEqual(ts_sec, 1000 + i)
            self.assertEqual(ts_frac, i * 1000)

    def test_all_byte_values_preserved(self):
        payload = bytes(range(256))
        result = read_pcap(file_object=_write([(payload, 0, 0)]))
        self.assertEqual(result.packets[0][0], payload)

    def test_variable_length_packets(self):
        pkts = [(bytes(n), 0, n) for n in (1, 20, 300)]
        result = read_pcap(file_object=_write(pkts))
        for (orig, _, _), (parsed, _, _) in zip(pkts, result.packets):
            self.assertEqual(parsed, orig)


# ---------------------------------------------------------------------------
# Roundtrip: write_pcapng → read_pcap
# ---------------------------------------------------------------------------

class TestReadPcapngRoundtrip(unittest.TestCase):
    def _roundtrip(self, packets, **kwargs):
        return read_pcap(file_object=_write(packets, **kwargs))

    def test_single_packet_roundtrip(self):
        payload = b"\xca\xfe\xba\xbe" * 10
        result = self._roundtrip([(payload, 1000, 500)])
        self.assertEqual(result.packets[0], (payload, 1000, 500))

    def test_multiple_packets_roundtrip(self):
        pkts = [(bytes([i] * (i + 1)), 1000 + i, i * 100) for i in range(8)]
        result = self._roundtrip(pkts)
        self.assertEqual([(d, s, u) for d, s, u in result.packets], pkts)

    def test_link_type_roundtrip_ethernet(self):
        result = self._roundtrip([(b"\x00" * 14, 0, 0)], link_type=LINKTYPE_ETHERNET)
        self.assertEqual(result.header.link_type, LINKTYPE_ETHERNET)

    def test_link_type_roundtrip_raw(self):
        result = self._roundtrip([(b"\x45" + b"\x00" * 19, 0, 0)], link_type=LINKTYPE_RAW)
        self.assertEqual(result.header.link_type, LINKTYPE_RAW)

    def test_nanoseconds_roundtrip(self):
        result = self._roundtrip([(b"\x00" * 8, 1, 999_999_999)], nanoseconds=True)
        self.assertTrue(result.header.nanoseconds)
        self.assertEqual(result.packets[0][2], 999_999_999)

    def test_usec_roundtrip(self):
        result = self._roundtrip([(b"\x00" * 8, 1, 999_999)], nanoseconds=False)
        self.assertFalse(result.header.nanoseconds)
        self.assertEqual(result.packets[0][2], 999_999)

    def test_large_timestamp_roundtrip(self):
        ts_sec = 2**32 - 1  # max 32-bit value
        ts_us  = 999_999
        result = self._roundtrip([(b"\x00" * 8, ts_sec, ts_us)])
        self.assertEqual(result.packets[0][1], ts_sec)
        self.assertEqual(result.packets[0][2], ts_us)


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

class TestReadPcapngFailure(unittest.TestCase):
    def _make_pcapng_truncated_shb(self) -> io.BytesIO:
        """Build a pcapng with a truncated SHB (only 6 bytes)."""
        return io.BytesIO(struct.pack("<I", 0x0A0D0D0A) + b"\x00" * 6)

    def test_truncated_shb_raises(self):
        with self.assertRaises(ValueError):
            read_pcap(file_object=self._make_pcapng_truncated_shb())

    def test_bad_bom_raises(self):
        # Valid SHB type and length but wrong byte-order magic
        buf = io.BytesIO()
        buf.write(struct.pack("<II", 0x0A0D0D0A, 28))  # SHB type + length
        buf.write(struct.pack("<I", 0xDEADBEEF))         # bad BOM
        buf.write(b"\x00" * 16)
        buf.seek(0)
        with self.assertRaises(ValueError):
            read_pcap(file_object=buf)

    def test_truncated_epb_body_raises(self):
        # Build a valid pcapng then corrupt an EPB body
        raw = bytearray(_write([(b"\x00" * 10, 0, 0)]).read())
        # Shrink EPB total_len to below minimum
        shb_len, = struct.unpack_from("<I", raw, 4)
        idb_len, = struct.unpack_from("<I", raw, shb_len + 4)
        epb_off = shb_len + idb_len
        # Truncate the file to cut the EPB body short
        bad = io.BytesIO(bytes(raw[:epb_off + 16]))  # only 16 bytes of EPB
        with self.assertRaises(ValueError):
            read_pcap(file_object=bad)


if __name__ == "__main__":
    unittest.main()
