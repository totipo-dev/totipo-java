package dev.totipo.format;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/** Canonical u16be framing; close clears owned scratch bytes, never returned copies. */
final class TlvWriter implements AutoCloseable {
    private final Buffer bytes = new Buffer();
    private boolean closed;

    TlvWriter field(int tag, byte[] value) {
        requireOpen();
        if (tag < 0 || tag > 0xffff || value.length > 0xffff) {
            throw new IllegalArgumentException("TLV outside u16 bounds");
        }
        bytes.reserve(4 + value.length);
        bytes.write(tag >>> 8); bytes.write(tag);
        bytes.write(value.length >>> 8); bytes.write(value.length);
        bytes.writeBytes(value);
        return this;
    }

    byte[] bytes() { requireOpen(); return bytes.toByteArray(); }

    @Override public void close() {
        bytes.clear();
        closed = true;
    }

    private void requireOpen() {
        if (closed) throw new IllegalStateException("Closed TLV writer");
    }

    private static final class Buffer extends ByteArrayOutputStream {
        // Reserve explicitly so resizing does not abandon a secret-bearing old buffer.
        void reserve(int additional) {
            int required = Math.addExact(count, additional);
            if (required > buf.length) {
                byte[] previous = buf;
                buf = Arrays.copyOf(previous, Math.max(required, buf.length * 2));
                Arrays.fill(previous, (byte) 0);
            }
        }

        void clear() { Arrays.fill(buf, (byte) 0); reset(); }
    }
}
