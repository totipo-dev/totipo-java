package org.totipo;

import java.util.Arrays;
import java.util.Objects;
/** Caller-owned secret ingress. Never represents a secret exported from a vault. */
public final class NewSecret implements AutoCloseable {
    private byte[] bytes;
    private NewSecret(byte[] input) {
        Objects.requireNonNull(input);
        if (input.length < 1 || input.length > 128) throw new IllegalArgumentException("Secret length");
        bytes = input.clone();
    }
    public static NewSecret copyOf(byte[] secret) { return new NewSecret(secret); }
    /** Owned ingress copy; caller must wipe it. Builders use and wipe this copy internally. */
    public synchronized byte[] copy() {
        if (bytes == null) throw new IllegalStateException("New secret closed");
        return bytes.clone();
    }
    @Override public synchronized void close() { if (bytes != null) Arrays.fill(bytes, (byte) 0); bytes = null; }
    @Override public String toString() { return "NewSecret[redacted]"; }
}

