package org.totipo.format;

import java.util.Arrays;

/** Owned fixed-width bytes with content equality; never exposes its backing array. */
final class SecurityBytes {
    private final byte[] bytes;

    SecurityBytes(byte[] bytes, int width) {
        if (bytes.length != width) { throw new IllegalArgumentException("Incorrect security field width"); }
        this.bytes = bytes.clone();
    }

    byte[] bytes() { return bytes.clone(); }
    int size() { return bytes.length; }

    /** Only session-owned values may be destroyed, after removal from equality maps. */
    void clear() { Arrays.fill(bytes, (byte) 0); }

    @Override public boolean equals(Object other) {
        return other instanceof SecurityBytes value && Arrays.equals(bytes, value.bytes);
    }
    @Override public int hashCode() { return Arrays.hashCode(bytes); }
    @Override public String toString() { return "SecurityBytes[redacted]"; }
}
