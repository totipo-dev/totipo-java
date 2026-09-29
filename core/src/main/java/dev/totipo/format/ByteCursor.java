package dev.totipo.format;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/** Internal synchronous reader; borrows input, but every returned byte slice is owned. */
final class ByteCursor {
    private final byte[] bytes;
    private final int end;
    private int position;

    ByteCursor(byte[] bytes, int offset, int length) {
        Objects.requireNonNull(bytes, "bytes");
        // Subtraction avoids overflow even for adversarial Java slice arguments.
        if (offset < 0 || length < 0 || offset > bytes.length || length > bytes.length - offset) {
            throw new IndexOutOfBoundsException("Invalid byte slice");
        }
        this.bytes = bytes;
        position = offset;
        end = offset + length;
    }

    void require(int length) throws TruncatedInput {
        if (length < 0) {
            throw new IllegalArgumentException("Negative read length");
        }
        if (length > end - position) {
            throw new TruncatedInput();
        }
    }

    int u8() throws TruncatedInput {
        require(1);
        // Mask before widening so Java's signed byte never changes wire values.
        return bytes[position++] & 0xff;
    }

    int u16be() throws TruncatedInput {
        require(2);
        return (u8() << 8) | u8();
    }

    long u32be() throws TruncatedInput {
        require(4);
        return ((long) u16be() << 16) | u16be();
    }

    int remaining() {
        return end - position;
    }

    int position() {
        return position;
    }

    BigInteger u64be() throws TruncatedInput {
        // Positive BigInteger preserves the whole unsigned range without date conversion.
        return new BigInteger(1, copy(8));
    }

    byte[] copy(int length) throws TruncatedInput {
        require(length);
        byte[] value = Arrays.copyOfRange(bytes, position, position + length);
        position += length;
        return value;
    }

    /** Intentional internal signal, converted into a parse failure at the boundary. */
    static final class TruncatedInput extends Exception {
        private static final long serialVersionUID = 1L;
    }
}
