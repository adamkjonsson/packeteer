import struct


def ones_complement_checksum(data: bytes) -> int:
    """RFC 1071 internet checksum over arbitrary bytes."""
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += struct.unpack_from('!H', data, i)[0]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF
