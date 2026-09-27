package dev.totipo.format;

/** Cryptographic unwrap result only; UNLOCKED does not mean durably established. */
final class VaultUnlockResult {
    enum Status { UNLOCKED, INVALID_FORMAT, INVALID_PASSWORD_INPUT, AUTHENTICATION_FAILED }

    private final Status status;
    private final byte[] root;

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
    byte[] root() { return root == null ? null : root.clone(); }

    /** Pure r13 §10 derivation, without any durable establishment or comparison. */
    byte[] binding() {
        if (root == null) {
            throw new IllegalStateException("No authenticated root");
        }
        return CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
    }

    @Override
    public String toString() { return "VaultUnlockResult[" + status + "]"; }
}
