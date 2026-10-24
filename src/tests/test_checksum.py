import random
import struct
import unittest

from packeteer.generate.checksum import crc32c, ones_complement_checksum


def _reference_checksum(data: bytes) -> int:
    """Sum word by word, as packeteer computed RFC 1071 before #213."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += struct.unpack_from('!H', data, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


class TestChecksum(unittest.TestCase):
    def test_all_zeros(self):
        result = ones_complement_checksum(b'\x00\x00')
        self.assertEqual(result, 0xFFFF)

    def test_odd_length_padded(self):
        # Padding a single byte \x01 should give same result as \x01\x00
        self.assertEqual(
            ones_complement_checksum(b'\x01'),
            ones_complement_checksum(b'\x01\x00'),
        )

    def test_rfc1071_example(self):
        # Verification: checksum of data + checksum over data should equal 0
        data = b'\x00\x01\xf2\x03\xf4\xf5\xf6\xf7'
        cksum = ones_complement_checksum(data)
        verify = ones_complement_checksum(data + struct.pack('!H', cksum))
        self.assertEqual(verify, 0)

    def test_rfc1071_worked_sum(self):
        # RFC 1071 §3: these words sum to 0xDDF2, so the checksum is ~0xDDF2.
        data = b'\x00\x01\xf2\x03\xf4\xf5\xf6\xf7'
        self.assertEqual(ones_complement_checksum(data), ~0xDDF2 & 0xFFFF)

    def test_known_ip_header(self):
        # Build a header ourselves and verify the checksum round-trips to 0
        from packeteer.generate.ip import IPHeader, _build_ip_header
        raw = _build_ip_header(IPHeader("192.168.0.1", "10.0.0.1", 6), b'\x00' * 20)
        self.assertEqual(ones_complement_checksum(raw), 0)


class TestChecksumMatchesTheWordSum(unittest.TestCase):
    """The sum in C gives what the word-by-word sum gave (#213)."""

    def test_random_buffers_of_every_short_length(self):
        rng = random.Random(213)
        for length in range(71):
            for _ in range(20):
                data = rng.randbytes(length)
                with self.subTest(length=length, data=data.hex()):
                    self.assertEqual(ones_complement_checksum(data),
                                     _reference_checksum(data))

    def test_frame_sized_buffers(self):
        rng = random.Random(1071)
        for length in (1499, 1500, 1501, 9000, 9001, 65535):
            data = rng.randbytes(length)
            with self.subTest(length=length):
                self.assertEqual(ones_complement_checksum(data),
                                 _reference_checksum(data))

    def test_edge_values(self):
        cases = [
            b'',                    # nothing at all: the sum is 0
            b'\x00',
            bytes(1500),            # all zero, any length
            b'\xff\xff',            # one word of 0xFFFF
            b'\xff' * 1501,         # all ones, odd length
            b'\xff\xfe\x00\x01',    # words summing to exactly 0xFFFF
            b'\x80\x00\x7f\xff',    # likewise, by a different route
            b'\xff\xff\xff\xff',    # 0x1FFFE, which folds to 0xFFFF
            b'\x00\x01' * 0xFFFF,   # 0xFFFF ones: a multiple of 0xFFFF
        ]
        for data in cases:
            with self.subTest(data=data[:8].hex(), length=len(data)):
                self.assertEqual(ones_complement_checksum(data),
                                 _reference_checksum(data))

    def test_the_result_is_always_sixteen_bits(self):
        rng = random.Random(16)
        for _ in range(500):
            result = ones_complement_checksum(rng.randbytes(rng.randrange(1, 64)))
            self.assertGreaterEqual(result, 0)
            self.assertLessEqual(result, 0xFFFF)


class TestCRC32c(unittest.TestCase):
    def test_check_value(self):
        # The standard check value: CRC-32c of the ASCII digits 1-9.
        self.assertEqual(crc32c(b'123456789'), 0xE3069283)


if __name__ == '__main__':
    unittest.main()
