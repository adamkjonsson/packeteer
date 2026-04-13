import io
import struct
import unittest

from packeteer.generator.pcap import write_pcap, LINKTYPE_ETHERNET, LINKTYPE_RAW
from packeteer.parser.pcap import read_pcap, PcapFile, PcapFileHeader

# Both endiannesses share the same magic value; byte order in the file
# is determined by how the bytes were packed (endian prefix in struct).
_MAGIC_USEC = 0xA1B2C3D4
_MAGIC_NSEC = 0xA1B23C4D
_GLOBAL_HDR_SIZE = 24
_PKT_HDR_SIZE = 16


def _write(packets, link_type=LINKTYPE_ETHERNET) -> io.BytesIO:
    """Helper: write packets to a BytesIO and rewind."""
    buf = io.BytesIO()
    write_pcap(packets, file_object=buf, link_type=link_type)
    buf.seek(0)
    return buf


def _make_raw_pcap(
    packets: list[tuple[bytes, int, int]],
    *,
    endian: str = "<",
    magic: int = _MAGIC_USEC,
    link_type: int = LINKTYPE_ETHERNET,
) -> io.BytesIO:
    """Build a pcap file by hand to test endian / magic variants."""
    buf = io.BytesIO()
    buf.write(struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, 65535, link_type))
    for data, ts_sec, ts_usec in packets:
        buf.write(struct.pack(endian + "IIII", ts_sec, ts_usec, len(data), len(data)))
        buf.write(data)
    buf.seek(0)
    return buf


# ---------------------------------------------------------------------------
# Global header parsing
# ---------------------------------------------------------------------------

class TestReadPcapGlobalHeader(unittest.TestCase):
    def _header(self, **kw) -> PcapFileHeader:
        return read_pcap(file_object=_write([(b"\x00" * 10, 0, 0)], **kw)).header

    def test_link_type_ethernet(self):
        self.assertEqual(self._header(link_type=LINKTYPE_ETHERNET).link_type, LINKTYPE_ETHERNET)

    def test_link_type_raw(self):
        self.assertEqual(self._header(link_type=LINKTYPE_RAW).link_type, LINKTYPE_RAW)

    def test_version_major(self):
        self.assertEqual(self._header().version_major, 2)

    def test_version_minor(self):
        self.assertEqual(self._header().version_minor, 4)

    def test_snaplen(self):
        self.assertEqual(self._header().snaplen, 65535)

    def test_nanoseconds_false_for_usec_magic(self):
        self.assertFalse(self._header().nanoseconds)

    def test_nanoseconds_true_for_nsec_magic(self):
        buf = _make_raw_pcap([(b"\x00" * 10, 0, 0)], magic=_MAGIC_NSEC)
        hdr = read_pcap(file_object=buf).header
        self.assertTrue(hdr.nanoseconds)


# ---------------------------------------------------------------------------
# Packet data and timestamps
# ---------------------------------------------------------------------------

class TestReadPcapPackets(unittest.TestCase):
    def test_empty_file_returns_no_packets(self):
        result = read_pcap(file_object=_write([]))
        self.assertEqual(result.packets, [])

    def test_single_packet_data(self):
        payload = b"\xde\xad\xbe\xef"
        result = read_pcap(file_object=_write([(payload, 0, 0)]))
        self.assertEqual(result.packets[0][0], payload)

    def test_single_packet_count(self):
        result = read_pcap(file_object=_write([(b"\x00" * 20, 0, 0)]))
        self.assertEqual(len(result.packets), 1)

    def test_multiple_packets_count(self):
        pkts = [(bytes([i] * 10), 0, i) for i in range(5)]
        result = read_pcap(file_object=_write(pkts))
        self.assertEqual(len(result.packets), 5)

    def test_multiple_packets_data_preserved(self):
        pkts = [(bytes([i] * 10), 0, i) for i in range(5)]
        result = read_pcap(file_object=_write(pkts))
        for i, (data, _, _) in enumerate(result.packets):
            self.assertEqual(data, bytes([i] * 10))

    def test_timestamp_seconds(self):
        result = read_pcap(file_object=_write([(b"\x00" * 10, 1700000000, 0)]))
        self.assertEqual(result.packets[0][1], 1700000000)

    def test_timestamp_usec(self):
        result = read_pcap(file_object=_write([(b"\x00" * 10, 0, 123456)]))
        self.assertEqual(result.packets[0][2], 123456)

    def test_timestamp_order_preserved(self):
        pkts = [(b"\x00" * 4, 1000 + i, i * 1000) for i in range(4)]
        result = read_pcap(file_object=_write(pkts))
        for i, (_, ts_sec, ts_usec) in enumerate(result.packets):
            self.assertEqual(ts_sec, 1000 + i)
            self.assertEqual(ts_usec, i * 1000)

    def test_variable_length_packets(self):
        pkts = [(bytes(n), 0, n) for n in (1, 20, 300)]
        result = read_pcap(file_object=_write(pkts))
        for (orig, _, _), (parsed, _, _) in zip(pkts, result.packets):
            self.assertEqual(parsed, orig)

    def test_all_byte_values_preserved(self):
        payload = bytes(range(256))
        result = read_pcap(file_object=_write([(payload, 0, 0)]))
        self.assertEqual(result.packets[0][0], payload)


# ---------------------------------------------------------------------------
# Endianness and magic variants
# ---------------------------------------------------------------------------

class TestReadPcapEndianness(unittest.TestCase):
    def test_little_endian_usec(self):
        buf = _make_raw_pcap([(b"\xaa" * 8, 5, 500)], endian="<", magic=_MAGIC_USEC)
        result = read_pcap(file_object=buf)
        self.assertEqual(result.packets[0][1], 5)
        self.assertEqual(result.packets[0][2], 500)
        self.assertFalse(result.header.nanoseconds)

    def test_big_endian_usec(self):
        buf = _make_raw_pcap([(b"\xbb" * 8, 5, 500)], endian=">", magic=_MAGIC_USEC)
        result = read_pcap(file_object=buf)
        self.assertEqual(result.packets[0][1], 5)
        self.assertEqual(result.packets[0][2], 500)
        self.assertFalse(result.header.nanoseconds)

    def test_little_endian_nsec(self):
        buf = _make_raw_pcap([(b"\xcc" * 4, 10, 999999999)], endian="<", magic=_MAGIC_NSEC)
        result = read_pcap(file_object=buf)
        self.assertTrue(result.header.nanoseconds)
        self.assertEqual(result.packets[0][2], 999999999)

    def test_big_endian_link_type_preserved(self):
        buf = _make_raw_pcap([(b"\x00" * 4, 0, 0)], endian=">", magic=_MAGIC_USEC, link_type=LINKTYPE_RAW)
        result = read_pcap(file_object=buf)
        self.assertEqual(result.header.link_type, LINKTYPE_RAW)


# ---------------------------------------------------------------------------
# Failure cases
# ---------------------------------------------------------------------------

class TestReadPcapFailure(unittest.TestCase):
    def test_bad_magic_raises(self):
        buf = io.BytesIO(b"\x00" * 24)
        with self.assertRaises(ValueError):
            read_pcap(file_object=buf)

    def test_truncated_global_header_raises(self):
        buf = io.BytesIO(b"\x00" * 10)
        with self.assertRaises(ValueError):
            read_pcap(file_object=buf)

    def test_truncated_packet_header_raises(self):
        buf = _write([(b"\x00" * 10, 0, 0)])
        data = buf.read()
        # Append an incomplete packet header (only 8 of 16 bytes)
        buf = io.BytesIO(data + b"\x00" * 8)
        with self.assertRaises(ValueError):
            read_pcap(file_object=buf)

    def test_truncated_packet_data_raises(self):
        buf = _write([(b"\x00" * 10, 0, 0)])
        data = buf.read()
        # Append a packet header claiming 20 bytes but supply only 4
        buf = io.BytesIO(data + struct.pack("<IIII", 0, 0, 20, 20) + b"\x00" * 4)
        with self.assertRaises(ValueError):
            read_pcap(file_object=buf)

    def test_neither_path_nor_file_object_raises(self):
        with self.assertRaises(ValueError):
            read_pcap()

    def test_both_path_and_file_object_raises(self):
        with self.assertRaises(ValueError):
            read_pcap(path="x.pcap", file_object=io.BytesIO())


# ---------------------------------------------------------------------------
# Roundtrip: write_pcap → read_pcap
# ---------------------------------------------------------------------------

class TestReadPcapRoundtrip(unittest.TestCase):
    def _roundtrip(self, packets, link_type=LINKTYPE_ETHERNET):
        return read_pcap(file_object=_write(packets, link_type=link_type))

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

    def test_result_is_pcap_file_instance(self):
        result = self._roundtrip([(b"\x00" * 10, 0, 0)])
        self.assertIsInstance(result, PcapFile)
        self.assertIsInstance(result.header, PcapFileHeader)


if __name__ == "__main__":
    unittest.main()
