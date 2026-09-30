package dev.totipo.format;

/** Internal result with an owned root. Storage observation statuses are provisional API-design debt. */
final class VaultUnlockResult implements AutoCloseable {
    enum Status { UNLOCKED, ABSENT, UNAVAILABLE, INVALID_FORMAT, INVALID_PASSWORD_INPUT, AUTHENTICATION_FAILED }

    private final Status status;
    private final byte[] root;
    private boolean closed;

    private VaultUnlockResult(Status status, byte[] root) {
        this.status = status;
        this.root = root == null ? null : root.clone();
    }

    static VaultUnlockResult unlocked(byte[] root) {
        if (root.length != 32) {
            throw new IllegalArgumentException("Root key must be 32 bytes");
        }
        return new VaultUnlockResult(Status.UNLOCKED, root);
    }

    static VaultUnlockResult failure(Status status) {
        if (status == Status.UNLOCKED) {
            throw new IllegalArgumentException("Successful unlock requires a root");
        }
        return new VaultUnlockResult(status, null);
    }

    Status status() { return status; }

    /** Caller owns the copy. No key bytes appear in toString, errors, or logs. */
    byte[] root() { requireOpen(); return root == null ? null : root.clone(); }

    /** Exact v1 fingerprint of the authenticated root; caller owns the result. */
    byte[] fingerprint() {
        requireOpen();
        if (root == null) {
            throw new IllegalStateException("No authenticated root");
        }
        return CryptoSupport.vaultFingerprint(root);
    }

    private void requireOpen() {
        if (closed) { throw new IllegalStateException("Unlock result closed"); }
    }

    /** Best-effort wipe; the JVM does not guarantee secure erasure. */
    @Override public void close() {
        if (root != null) { java.util.Arrays.fill(root, (byte) 0); }
        closed = true;
    }

    @Override
    public String toString() { return "VaultUnlockResult[" + status + "]"; }
}
