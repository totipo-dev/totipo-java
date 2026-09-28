package dev.totipo.format;

import java.security.GeneralSecurityException;

/**
 * App-local P-256 provenance capability, bound to one persisted VAULT_BINDING.
 * Attribution only: possession does not grant semantic write authority.
 * Implementations may use non-exportable platform keys; no private representation
 * or provider handle is part of this contract. Handles are synchronous and thread-confined.
 */
public interface DeviceProvenanceKey extends AutoCloseable {
    /** Returns a fresh defensive copy of the exact persisted 32-byte binding. */
    byte[] vaultBinding();

    /** Returns a fresh defensive copy of canonical 0x04 || X[32] || Y[32]. */
    byte[] publicKeyX963();

    /**
     * SHA256withECDSA over the exact message (not a caller-supplied digest).
     * Borrows message synchronously, without modification or retention beyond return.
     * Rejects null with NullPointerException before provider use. Returns a fresh,
     * caller-owned nonempty canonical DER signature of at most 72 bytes. Both high-S
     * and low-S are valid. Uses platform signing/nonce generation. Throws on failure.
     * All operations except close must fail after close.
     */
    byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException;

    /** Idempotently releases this handle; must not delete the persistent identity. */
    @Override void close();
}
