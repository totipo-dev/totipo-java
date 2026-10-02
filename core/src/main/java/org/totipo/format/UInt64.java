package org.totipo.format;

import java.nio.ByteBuffer;

/** All unsigned u64 values; raw bits have no time or freshness policy. */
record UInt64(long rawBits) implements Comparable<UInt64> {
    static UInt64 fromBytes(byte[] bytes) {
        if (bytes.length != 8) throw new IllegalArgumentException("u64 must be eight bytes");
        return new UInt64(ByteBuffer.wrap(bytes).getLong());
    }

    byte[] bytes() { return ByteBuffer.allocate(8).putLong(rawBits).array(); }
    @Override public int compareTo(UInt64 other) { return Long.compareUnsigned(rawBits, other.rawBits); }
    @Override public String toString() { return Long.toUnsignedString(rawBits); }
}
