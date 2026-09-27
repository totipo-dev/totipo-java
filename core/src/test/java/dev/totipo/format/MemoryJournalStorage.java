package dev.totipo.format;

import java.io.*;
import java.util.Arrays;

/** Exact byte test fake; makes no production durability claim. */
final class MemoryJournalStorage implements SecurityMemoryStorage {
    byte[] bytes;
    boolean failAppend;
    int partial = -1;
    Runnable beforeAppend = () -> {};
    int appends;
    @Override public InputStream openRead() { return bytes == null ? null : new ByteArrayInputStream(bytes.clone()); }
    @Override public void initializeDurably(byte[] header) throws IOException {
        if (bytes != null) { throw new IOException("Already exists"); }
        bytes = header.clone();
    }
    @Override public void appendDurably(byte[] frame) throws IOException {
        beforeAppend.run();
        if (bytes == null || failAppend) { throw new IOException("Injected append failure"); }
        int count = partial < 0 ? frame.length : Math.min(partial, frame.length);
        byte[] next = Arrays.copyOf(bytes, bytes.length + count);
        System.arraycopy(frame, 0, next, bytes.length, count); bytes = next;
        if (partial >= 0) { throw new IOException("Injected interrupted append"); }
        appends++;
    }
    @Override public void truncateDurably(long offset) throws IOException {
        if (bytes == null || offset < 0 || offset > bytes.length) { throw new IOException("Invalid repair"); }
        bytes = Arrays.copyOf(bytes, Math.toIntExact(offset));
    }
    @Override public void close() {}
}
