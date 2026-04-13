import io
import struct
import unittest

from packeteer.pcap import write_pcapng, LINKTYPE_ETHERNET, LINKTYPE_RAW

_SHB_TYPE = 0x0A0D0D0A
_IDB_TYPE = 0x00000001
_EPB_TYPE = 0x00000006
_BOM      = 0x1A2B3C4D


def _write(packets, **kwargs) -> io.BytesIO:
    buf = io.BytesIO()
    write_pcapng(packets, file_object=buf, **kwargs)
    buf.seek(0)
    return buf


def _read_block(data: bytes, offset: int) -> tuple[int, bytes]:
    """Return (block_type, body_bytes) at *offset*."""
    block_type, total_len = struct.unpack_from("<II", data, offset)
    body = data[offset + 8 : offset + total_len - 4]
    return block_type, body


class TestWritePcapngSHB(unittest.TestCase):
    def _raw(self) -> bytes:
        return _write([(b"\x00" * 10, 0, 0)]).read()

    def test_shb_block_type(self):
        raw = self._raw()
        (block_type,) = struct.unpack_from("<I", raw, 0)
        self.assertEqual(block_type, _SHB_TYPE)

    def test_shb_byte_order_magic(self):
        raw = self._raw()
        (bom,) = struct.unpack_from("<I", raw, 8)
        self.assertEqual(bom, _BOM)

    def test_shb_version(self):
        raw = self._raw()
        major, minor = struct.unpack_from("<HH", raw, 12)
        self.assertEqual(major, 1)
        self.assertEqual(minor, 0)

    def test_shb_total_length(self):
        raw = self._raw()
        (total_len,) = struct.unpack_from("<I", raw, 4)
        self.assertEqual(total_len, 28)  # 4+4+16+4

    def test_shb_total_length_repeated(self):
        raw = self._raw()
        (total_len,) = struct.unpack_from("<I", raw, 4)
        (trailing,)  = struct.unpack_from("<I", raw, total_len - 4)
        self.assertEqual(total_len, trailing)


class TestWritePcapngIDB(unittest.TestCase):
    def _idb_offset(self, raw: bytes) -> int:
        shb_len, = struct.unpack_from("<I", raw, 4)
        return shb_len

    def _idb_body(self, **kwargs) -> bytes:
        raw = _write([(b"\x00" * 10, 0, 0)], **kwargs).read()
        _, body = _read_block(raw, self._idb_offset(raw))
        return body

    def test_idb_block_type(self):
        raw = _write([(b"\x00" * 10, 0, 0)]).read()
        block_type, _ = _read_block(raw, self._idb_offset(raw))
        self.assertEqual(block_type, _IDB_TYPE)

    def test_idb_link_type_ethernet(self):
        body = self._idb_body(link_type=LINKTYPE_ETHERNET)
        link_type, = struct.unpack_from("<H", body, 0)
        self.assertEqual(link_type, LINKTYPE_ETHERNET)

    def test_idb_link_type_raw(self):
        body = self._idb_body(link_type=LINKTYPE_RAW)
        link_type, = struct.unpack_from("<H", body, 0)
        self.assertEqual(link_type, LINKTYPE_RAW)

    def test_idb_snaplen(self):
        body = self._idb_body()
        snaplen, = struct.unpack_from("<I", body, 4)
        self.assertEqual(snaplen, 65535)

    def test_idb_tsresol_microseconds(self):
        body = self._idb_body(nanoseconds=False)
        opt_code, opt_len = struct.unpack_from("<HH", body, 8)
        self.assertEqual(opt_code, 9)
        self.assertEqual(opt_len, 1)
        self.assertEqual(body[12], 6)   # 10^-6

    def test_idb_tsresol_nanoseconds(self):
        body = self._idb_body(nanoseconds=True)
        opt_code, opt_len = struct.unpack_from("<HH", body, 8)
        self.assertEqual(opt_code, 9)
        self.assertEqual(opt_len, 1)
        self.assertEqual(body[12], 9)   # 10^-9

    def test_idb_total_length_repeated(self):
        raw = _write([(b"\x00" * 10, 0, 0)]).read()
        off = self._idb_offset(raw)
        idb_total, = struct.unpack_from("<I", raw, off + 4)
        trailing,  = struct.unpack_from("<I", raw, off + idb_total - 4)
        self.assertEqual(idb_total, trailing)


class TestWritePcapngEPB(unittest.TestCase):
    def _epb_offset(self, raw: bytes) -> int:
        shb_len, = struct.unpack_from("<I", raw, 4)
        idb_len, = struct.unpack_from("<I", raw, shb_len + 4)
        return shb_len + idb_len

    def _epb_body(self, packets, **kwargs) -> bytes:
        raw = _write(packets, **kwargs).read()
        _, body = _read_block(raw, self._epb_offset(raw))
        return body

    def test_epb_block_type(self):
        raw = _write([(b"\x00" * 10, 0, 0)]).read()
        block_type, _ = _read_block(raw, self._epb_offset(raw))
        self.assertEqual(block_type, _EPB_TYPE)

    def test_epb_interface_id_zero(self):
        body = self._epb_body([(b"\x00" * 10, 0, 0)])
        iface_id, = struct.unpack_from("<I", body, 0)
        self.assertEqual(iface_id, 0)

    def test_epb_packet_data_preserved(self):
        payload = bytes(range(20))
        body = self._epb_body([(payload, 0, 0)])
        cap_len, = struct.unpack_from("<I", body, 12)
        self.assertEqual(cap_len, len(payload))
        self.assertEqual(body[20 : 20 + cap_len], payload)

    def test_epb_captured_equals_original_length(self):
        payload = b"\xab" * 15
        body = self._epb_body([(payload, 0, 0)])
        cap_len, orig_len = struct.unpack_from("<II", body, 12)
        self.assertEqual(cap_len, orig_len)

    def test_epb_total_length_is_multiple_of_4(self):
        for size in (1, 2, 3, 4, 5, 10, 15, 16):
            raw = _write([(bytes(size), 0, 0)]).read()
            epb_total, = struct.unpack_from("<I", raw, self._epb_offset(raw) + 4)
            self.assertEqual(epb_total % 4, 0, f"size={size}")

    def test_epb_total_length_repeated(self):
        raw = _write([(b"\x00" * 10, 0, 0)]).read()
        off = self._epb_offset(raw)
        epb_total, = struct.unpack_from("<I", raw, off + 4)
        trailing,  = struct.unpack_from("<I", raw, off + epb_total - 4)
        self.assertEqual(epb_total, trailing)

    def test_epb_timestamp_microseconds(self):
        ts_sec, ts_us = 1700000000, 123456
        body = self._epb_body([(b"\x00" * 8, ts_sec, ts_us)], nanoseconds=False)
        ts_hi, ts_lo = struct.unpack_from("<II", body, 4)
        ts64 = (ts_hi << 32) | ts_lo
        self.assertEqual(ts64, ts_sec * 1_000_000 + ts_us)

    def test_epb_timestamp_nanoseconds(self):
        ts_sec, ts_ns = 1700000000, 999_999_999
        body = self._epb_body([(b"\x00" * 8, ts_sec, ts_ns)], nanoseconds=True)
        ts_hi, ts_lo = struct.unpack_from("<II", body, 4)
        ts64 = (ts_hi << 32) | ts_lo
        self.assertEqual(ts64, ts_sec * 1_000_000_000 + ts_ns)

    def test_epb_zero_timestamp(self):
        body = self._epb_body([(b"\x00" * 8, 0, 0)])
        ts_hi, ts_lo = struct.unpack_from("<II", body, 4)
        self.assertEqual(ts_hi, 0)
        self.assertEqual(ts_lo, 0)


class TestWritePcapngStructure(unittest.TestCase):
    def test_empty_packet_list_has_shb_and_idb_only(self):
        raw = _write([]).read()
        shb_len, = struct.unpack_from("<I", raw, 4)
        idb_len, = struct.unpack_from("<I", raw, shb_len + 4)
        self.assertEqual(len(raw), shb_len + idb_len)

    def test_multiple_packets_each_get_epb(self):
        pkts = [(bytes([i] * 8), i, 0) for i in range(5)]
        raw = _write(pkts).read()
        shb_len, = struct.unpack_from("<I", raw, 4)
        idb_len, = struct.unpack_from("<I", raw, shb_len + 4)
        offset = shb_len + idb_len
        count = 0
        while offset < len(raw):
            block_type, = struct.unpack_from("<I", raw, offset)
            block_len,  = struct.unpack_from("<I", raw, offset + 4)
            self.assertEqual(block_type, _EPB_TYPE)
            count += 1
            offset += block_len
        self.assertEqual(count, 5)

    def test_file_object_receives_output(self):
        buf = io.BytesIO()
        write_pcapng([(b"\x00" * 10, 0, 0)], file_object=buf)
        self.assertGreater(buf.tell(), 0)

    def test_all_block_total_lengths_multiple_of_4(self):
        pkts = [(bytes(n), 0, 0) for n in (1, 2, 3, 5, 7, 11)]
        raw = _write(pkts).read()
        offset = 0
        while offset < len(raw):
            total_len, = struct.unpack_from("<I", raw, offset + 4)
            self.assertEqual(total_len % 4, 0, f"block at offset {offset}")
            offset += total_len


if __name__ == "__main__":
    unittest.main()
