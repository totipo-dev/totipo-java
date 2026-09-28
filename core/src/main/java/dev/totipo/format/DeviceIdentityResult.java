package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;

/** Thread-confined owned capability. Status is immutable; close/anomaly revokes use.
 * No raw signer escapes. Operations separately check identity binding. */
final class DeviceIdentityResult implements AutoCloseable {
    enum Status {
        AVAILABLE_BOUND, CREATED_BOUND, ABSENT,
        LOCAL_BINDING_ABSENT, LOCAL_BINDING_CORRUPT,
        KEY_STORAGE_UNAVAILABLE, KEY_BINDING_MISMATCH, KEY_MATERIAL_INVALID,
        KEY_ALREADY_EXISTS, KEY_CREATION_INCOMPLETE
    }
    private final Status status;
    private final byte[] binding, publicKey, deviceId;
    private DeviceProvenanceKey signer;

    private DeviceIdentityResult(Status status, DeviceProvenanceKey signer, byte[] binding, byte[] publicKey) {
        this.status = status;
        this.signer = signer;
        this.binding = binding == null ? null : binding.clone();
        this.publicKey = publicKey == null ? null : publicKey.clone();
        this.deviceId = publicKey == null ? null : P256.deviceId(publicKey);
    }
    static DeviceIdentityResult failure(Status status) { return new DeviceIdentityResult(status, null, null, null); }
    static DeviceIdentityResult bound(Status status, DeviceProvenanceKey signer, byte[] binding, byte[] key) {
        return new DeviceIdentityResult(status, signer, binding, key);
    }
    Status status() { return status; }
    private void requireAvailable() {
        if (signer == null) { throw new IllegalStateException("Identity unavailable or closed"); }
    }
    byte[] vaultBinding() { requireAvailable(); return binding.clone(); }
    byte[] publicKeyX963() { requireAvailable(); return publicKey.clone(); }
    byte[] deviceId() { requireAvailable(); return deviceId.clone(); }
    VerificationKeyMaterial.Candidate verificationCandidate() {
        requireAvailable();
        return new VerificationKeyMaterial.Candidate(deviceId, publicKey);
    }

    /** Synchronous owned copy prevents provider mutation of caller input. Every
     * returned signature is self-verified; an anomaly permanently closes this handle. */
    byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException {
        Objects.requireNonNull(message);
        requireAvailable();
        byte[] exact = message.clone();
        byte[] borrowed = exact.clone();
        try {
            byte[] supplied = signer.signSha256Ecdsa(borrowed);
            byte[] signature = supplied == null ? null : supplied.clone();
            if (signature == null || !EcdsaDerSignature.isCanonical(signature)
                    || !P256.verify(publicKey, exact, signature)) {
                throw new GeneralSecurityException("Invalid device signing result");
            }
            return signature;
        } catch (GeneralSecurityException | RuntimeException e) {
            try { close(); } catch (RuntimeException closing) { e.addSuppressed(closing); }
            throw new GeneralSecurityException("Device signer unusable", e);
        } finally {
            Arrays.fill(exact, (byte) 0);
            Arrays.fill(borrowed, (byte) 0);
        }
    }
    @Override public void close() {
        var owned = signer;
        signer = null;
        if (owned != null) { owned.close(); }
    }
    @Override public String toString() { return "DeviceIdentityResult[" + status + "]"; }
}
