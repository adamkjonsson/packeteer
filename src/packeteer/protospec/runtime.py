"""The reader and writer a compiled protocol uses.

Generated code calls these rather than emitting bit arithmetic inline.  A field
one bit wide and a field thirty-two bits wide then compile to the same shape of
call, which keeps the generated module something a reviewer can read — and it
puts the fiddly part in one tested place instead of in every generated module.

Both are byte-oriented until a spec asks for a field that is not a whole number
of bytes, at which point they carry a bit offset.  Sub-byte fields are read and
written most-significant bit first, which is how every protocol that has them
is specified.

A read past the end raises :class:`ValueError`.  That is what makes a decoder
refuse a truncated or mismatched payload, which in turn is what leaves someone
else's traffic on a shared port as an opaque payload instead of a wrong
message.
"""
from __future__ import annotations

__all__ = ["Reader", "Writer"]

_BITS_PER_BYTE = 8


class Reader:
    """A cursor over a message's bytes.

    Attributes:
        data: The bytes being read.

    """

    __slots__ = ("data", "_bit")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._bit = 0

    @property
    def bit_position(self) -> int:
        """How many bits have been read."""
        return self._bit

    @property
    def bits_left(self) -> int:
        """How many bits remain."""
        return len(self.data) * _BITS_PER_BYTE - self._bit

    def at_end(self) -> bool:
        """Whether everything has been read.

        Returns:
            ``True`` when no bits remain.

        """
        return self.bits_left <= 0

    def read_int(self, width: int, *, signed: bool = False,
                 little: bool = False) -> int:
        """Read *width* bits as an integer.

        Args:
            width: How many bits, 1 to 64.
            signed: Whether to read two's-complement.
            little: Whether a whole number of bytes is little-endian.  Ignored
                for a width that is not a multiple of eight, where byte order
                has no meaning.

        Returns:
            The value read.

        Raises:
            ValueError: If fewer than *width* bits remain.

        """
        if width > self.bits_left:
            raise ValueError(
                f"need {width} bits at bit {self._bit}, but only "
                f"{max(self.bits_left, 0)} remain",
            )
        value = 0
        if self._bit % _BITS_PER_BYTE == 0 and width % _BITS_PER_BYTE == 0:
            start = self._bit // _BITS_PER_BYTE
            chunk = self.data[start:start + width // _BITS_PER_BYTE]
            value = int.from_bytes(chunk, "little" if little else "big")
        else:
            for _ in range(width):
                byte = self.data[self._bit // _BITS_PER_BYTE]
                shift = _BITS_PER_BYTE - 1 - (self._bit % _BITS_PER_BYTE)
                value = (value << 1) | ((byte >> shift) & 1)
                self._bit += 1
            self._bit -= width          # restored by the common advance below
        self._bit += width
        if signed and width and value >= 1 << (width - 1):
            value -= 1 << width
        return value

    def read_bytes(self, count: int) -> bytes:
        """Read *count* bytes.

        Args:
            count: How many bytes.

        Returns:
            The bytes read.

        Raises:
            ValueError: If the cursor is not byte-aligned, *count* is
                negative, or fewer than *count* bytes remain.

        """
        if count < 0:
            raise ValueError(f"cannot read {count} bytes")
        if self._bit % _BITS_PER_BYTE:
            raise ValueError("a bytes field must start on a byte boundary")
        start = self._bit // _BITS_PER_BYTE
        if start + count > len(self.data):
            raise ValueError(
                f"need {count} bytes at offset {start}, but only "
                f"{len(self.data) - start} remain",
            )
        self._bit += count * _BITS_PER_BYTE
        return self.data[start:start + count]

    def read_rest(self) -> bytes:
        """Read everything left.

        Returns:
            The remaining bytes, empty when there are none.

        Raises:
            ValueError: If the cursor is not byte-aligned.

        """
        if self._bit % _BITS_PER_BYTE:
            raise ValueError("a bytes field must start on a byte boundary")
        start = self._bit // _BITS_PER_BYTE
        self._bit = len(self.data) * _BITS_PER_BYTE
        return self.data[start:]


class Writer:
    """A growing buffer a message is encoded into."""

    __slots__ = ("_out", "_pending", "_pending_bits")

    def __init__(self) -> None:
        self._out = bytearray()
        self._pending = 0
        self._pending_bits = 0

    def write_int(self, value: int, width: int, *, signed: bool = False,
                  little: bool = False) -> None:
        """Write *value* in *width* bits.

        Args:
            value: The value to write.
            width: How many bits, 1 to 64.
            signed: Whether to write two's-complement.
            little: Whether a whole number of bytes is little-endian.

        Raises:
            ValueError: If *value* does not fit in *width* bits.

        """
        if signed:
            low, high = -(1 << (width - 1)), (1 << (width - 1)) - 1
        else:
            low, high = 0, (1 << width) - 1
        if not low <= value <= high:
            raise ValueError(f"{value} does not fit in {width} "
                             f"{'signed' if signed else 'unsigned'} bits")
        masked = value & ((1 << width) - 1)
        if self._pending_bits == 0 and width % _BITS_PER_BYTE == 0:
            self._out += masked.to_bytes(width // _BITS_PER_BYTE,
                                         "little" if little else "big")
            return
        for shift in range(width - 1, -1, -1):
            self._pending = (self._pending << 1) | ((masked >> shift) & 1)
            self._pending_bits += 1
            if self._pending_bits == _BITS_PER_BYTE:
                self._out.append(self._pending)
                self._pending = 0
                self._pending_bits = 0

    def write_bytes(self, data: bytes) -> None:
        """Write *data* verbatim.

        Args:
            data: The bytes to write.

        Raises:
            ValueError: If a partial byte is pending, so *data* would not be
                byte-aligned.

        """
        if self._pending_bits:
            raise ValueError("a bytes field must start on a byte boundary")
        self._out += data

    def getvalue(self) -> bytes:
        """Return everything written.

        Returns:
            The encoded bytes.

        Raises:
            ValueError: If a partial byte is pending, which means the spec's
                bit fields do not add up to whole bytes.

        """
        if self._pending_bits:
            raise ValueError(
                f"{self._pending_bits} bits were written without completing a "
                "byte; the spec's bit fields do not add up",
            )
        return bytes(self._out)
