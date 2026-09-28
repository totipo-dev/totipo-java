package dev.totipo.format;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * App-local secret custody, separate from VaultBindingStore and
 * synchronized bootstrap/object storage. Different confidentiality, mutation and
 * hardware-backed-key requirements preclude combining these trust domains.
 * No portable private-key serialization format is specified. The caller owns the
 * store; each returned handle is independently owned by the caller.
 */
public interface DeviceProvenanceKeyStore extends AutoCloseable {
    /**
     * Nonmutating load. Null means genuine absence only. IOException means storage
     * unavailable; GeneralSecurityException means invalid/corrupt identity.
     * Never repairs, deletes, rebinds or generates an identity.
     */
    DeviceProvenanceKey openExisting() throws IOException, GeneralSecurityException;

    /**
     * Explicit independent secp256r1 key generation, atomically no-replace even
     * across processes. Reject null with NullPointerException and width other than
     * 32 with IllegalArgumentException before any mutation. Copy binding if retained.
     * Never derive the private key from binding, root, password or synchronized data.
     * Success means the key AND exact binding are durably retained under the platform
     * backend contract, the returned signer is that identity, and closing/reopening
     * loads the same identity. Existing identity/collision must fail (IOException).
     * Any failure may be ambiguous: no automatic retry; explicit load resolves it.
     * Backend must close transient handles on failure. No synchronized files, journal
     * frames, display name, author time or advertised state belong in this store.
     */
    DeviceProvenanceKey createDurably(byte[] vaultBinding) throws IOException, GeneralSecurityException;

    /** Releases store resources without deleting identities or invalidating returned handles. */
    @Override void close() throws IOException;
}
