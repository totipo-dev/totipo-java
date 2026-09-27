package dev.totipo.format;

import java.io.IOException;
import java.io.InputStream;

/**
 * Exclusive, synchronous storage of opaque local security-memory bytes outside the
 * synchronized vault namespace. An implementation holds exclusive access for its lifetime.
 * No method may retain or mutate caller arrays. Failures may leave an ambiguous suffix:
 * callers must stop writing and reopen/replay before further writes.
 */
public interface SecurityMemoryStorage extends AutoCloseable {
    /** Returns a stable bounded-memory stream, or null only when storage is absent.
     * Existing empty storage MUST return an empty stream. Caller closes the stream. */
    InputStream openRead() throws IOException;

    /** Create-new only; returns only after the header and new journal existence are
     * durable, including required containing-directory durability. Never replaces storage. */
    void initializeDurably(byte[] header) throws IOException;

    /** Returns successfully only after the entire complete frame is durable according
     * to the backend's crash-safety contract. Must append exactly once, in supplied order. */
    void appendDurably(byte[] frame) throws IOException;

    /** Returns only after truncation to the verified incomplete-tail repair offset is
     * durable. Only an explicitly validated incomplete suffix may be removed. */
    void truncateDurably(long offset) throws IOException;

    /** Releases exclusive access/resources; closing is not a substitute for durability. */
    @Override void close() throws IOException;
}
