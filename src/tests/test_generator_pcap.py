import io
import struct
import unittest
from packeteer.pcap import write_pcap, LINKTYPE_ETHERNET, LINKTYPE_RAW

_PCAP_MAGIC_NSEC = 0xA1B23C4D

_PCAP_MAGIC    = 0xA1B2C3D4
_PCAP_MAJOR    = 2
_PCAP_MINOR    = 4
_GLOBAL_HDR_SZ = 24
_PKT_HDR_SZ    = 16


class TestWritePcap(unittest.TestCase):
    def _parse_global(self, data: bytes) -> dict:
        magic, major, minor, zone, sigfigs, snaplen, network = struct.unpack_from('<IHHiIII', data)
        return dict(magic=magic, major=major, minor=minor, zone=zone,
                    sigfigs=sigfigs, snaplen=snaplen, network=network)

    def _parse_pkt_hdr(self, data: bytes, offset: int) -> dict:
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from('<IIII', data, offset)
        return dict(ts_sec=ts_sec, ts_usec=ts_usec, incl_len=incl_len, orig_len=orig_len)

    def test_global_header_magic(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 0, 0)], file_object = buf, link_type=LINKTYPE_ETHERNET)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['magic'], _PCAP_MAGIC)

    def test_global_header_version(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['major'], _PCAP_MAJOR)
        self.assertEqual(hdr['minor'], _PCAP_MINOR)

    def test_global_header_snaplen(self):
        buf = io.BytesIO()
        write_pcap( [(b'\x00' * 10, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['snaplen'], 65535)

    def test_global_header_link_type_ethernet(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['network'], LINKTYPE_ETHERNET)

    def test_global_header_link_type_raw(self):
        buf = io.BytesIO()
        write_pcap( [(b'\x00' * 10, 0, 0)], file_object=buf, link_type=LINKTYPE_RAW)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['network'], LINKTYPE_RAW)

    def test_single_packet_total_size(self):
        payload = b'\xAB' * 20
        buf = io.BytesIO()
        write_pcap([(payload, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(len(buf.getvalue()), _GLOBAL_HDR_SZ + _PKT_HDR_SZ + len(payload))

    def test_packet_header_lengths_match(self):
        payload = b'\x01\x02\x03\x04\x05'
        buf = io.BytesIO()
        write_pcap([(payload, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        phdr = self._parse_pkt_hdr(buf.getvalue(), _GLOBAL_HDR_SZ)
        self.assertEqual(phdr['incl_len'], len(payload))
        self.assertEqual(phdr['orig_len'], len(payload))

    def test_packet_data_preserved(self):
        payload = bytes(range(256))
        buf = io.BytesIO()
        write_pcap([(payload, 0, 0)], file_object=buf, link_type=LINKTYPE_ETHERNET)
        raw = buf.getvalue()
        data_offset = _GLOBAL_HDR_SZ + _PKT_HDR_SZ
        self.assertEqual(raw[data_offset:data_offset + len(payload)], payload)

    def test_multiple_packets(self):
        pkts = [(b'\xAA' * 10, 0, 0), (b'\xBB' * 20, 0, 1), (b'\xCC' * 5, 0, 2)]
        buf = io.BytesIO()
        write_pcap(pkts, file_object=buf, link_type=LINKTYPE_ETHERNET)
        raw = buf.getvalue()
        expected = _GLOBAL_HDR_SZ + sum(_PKT_HDR_SZ + len(p[0]) for p in pkts)
        self.assertEqual(len(raw), expected)

    def test_multiple_packets_data_intact(self):
        pkts = [(b'\xAA' * 10, 0, 0), (b'\xBB' * 20, 0, 1)]
        buf = io.BytesIO()
        write_pcap(pkts, file_object=buf, link_type=LINKTYPE_ETHERNET)
        raw = buf.getvalue()
        offset = _GLOBAL_HDR_SZ
        for pkt in pkts:
            phdr = self._parse_pkt_hdr(raw, offset)
            self.assertEqual(phdr['incl_len'], len(pkt[0]))
            offset += _PKT_HDR_SZ
            self.assertEqual(raw[offset:offset + len(pkt[0])], pkt[0])
            offset += len(pkt[0])

    def test_empty_packet_list(self):
        buf = io.BytesIO()
        write_pcap([], file_object=buf, link_type=LINKTYPE_ETHERNET)
        self.assertEqual(len(buf.getvalue()), _GLOBAL_HDR_SZ)


class TestWritePcapNanoseconds(unittest.TestCase):
    def _parse_global(self, data: bytes) -> dict:
        magic, major, minor, zone, sigfigs, snaplen, network = struct.unpack_from('<IHHiIII', data)
        return dict(magic=magic, major=major, minor=minor, zone=zone,
                    sigfigs=sigfigs, snaplen=snaplen, network=network)

    def _parse_pkt_hdr(self, data: bytes, offset: int) -> dict:
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack_from('<IIII', data, offset)
        return dict(ts_sec=ts_sec, ts_frac=ts_frac, incl_len=incl_len, orig_len=orig_len)

    def test_nsec_magic(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 0, 0)], file_object=buf, nanoseconds=True)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['magic'], _PCAP_MAGIC_NSEC)

    def test_usec_magic_by_default(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 0, 0)], file_object=buf)
        hdr = self._parse_global(buf.getvalue())
        self.assertEqual(hdr['magic'], _PCAP_MAGIC)

    def test_nsec_timestamp_fraction_preserved(self):
        buf = io.BytesIO()
        write_pcap([(b'\x00' * 10, 1234567890, 999_999_999)], file_object=buf, nanoseconds=True)
        phdr = self._parse_pkt_hdr(buf.getvalue(), _GLOBAL_HDR_SZ)
        self.assertEqual(phdr['ts_sec'], 1234567890)
        self.assertEqual(phdr['ts_frac'], 999_999_999)

    def test_nsec_file_size_same_as_usec(self):
        payload = b'\xAB' * 20
        buf_usec = io.BytesIO()
        buf_nsec = io.BytesIO()
        write_pcap([(payload, 0, 0)], file_object=buf_usec, nanoseconds=False)
        write_pcap([(payload, 0, 0)], file_object=buf_nsec, nanoseconds=True)
        self.assertEqual(len(buf_usec.getvalue()), len(buf_nsec.getvalue()))


if __name__ == '__main__':
    unittest.main()
