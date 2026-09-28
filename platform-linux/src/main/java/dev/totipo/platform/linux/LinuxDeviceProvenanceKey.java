package dev.totipo.platform.linux;

import dev.totipo.format.DeviceProvenanceKey;
import dev.totipo.format.DeviceProvenanceSignature;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Objects;

/** Independent in-memory signer; never refreshes from or deletes filesystem state. */
final class LinuxDeviceProvenanceKey implements DeviceProvenanceKey {
    private final byte[] binding, publicKey;
    private PrivateKey privateKey;
    private final SignatureOperation signing;
    private boolean closed;

    LinuxDeviceProvenanceKey(byte[] binding, byte[] publicKey, PrivateKey privateKey) {
        this(binding, publicKey, privateKey, LinuxDeviceProvenanceKey::sign);
    }
    /** Internal seam for provider-output contract tests. */
    @FunctionalInterface
    interface SignatureOperation {
        byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException;
    }
    LinuxDeviceProvenanceKey(byte[] binding, byte[] publicKey, PrivateKey privateKey, SignatureOperation signing) {
        this.binding = binding.clone(); this.publicKey = publicKey.clone(); this.privateKey = privateKey;
        this.signing = Objects.requireNonNull(signing);
    }
    private void requireOpen() { if (closed) throw new IllegalStateException("KEY_CLOSED"); }
    @Override public synchronized byte[] vaultBinding() { requireOpen(); return binding.clone(); }
    @Override public synchronized byte[] publicKeyX963() { requireOpen(); return publicKey.clone(); }
    @Override public synchronized byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException {
        Objects.requireNonNull(message); requireOpen();
        byte[] supplied = signing.sign(privateKey, message);
        if (supplied == null || supplied.length == 0 || supplied.length > 72)
            throw new GeneralSecurityException("INVALID_SIGNATURE_LENGTH");
        byte[] result = supplied.clone();
        DeviceProvenanceSignature.validateCanonicalDer(result);
        return result;
    }
    private static byte[] sign(PrivateKey key, byte[] message) throws GeneralSecurityException {
        var signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(key); signature.update(message);
        return signature.sign();
    }
    static void destroy(PrivateKey key) {
        if (key != null) try { key.destroy(); }
        catch (javax.security.auth.DestroyFailedException | RuntimeException ignored) { /* Best effort. */ }
    }
    @Override public synchronized void close() {
        if (closed) return;
        closed = true;
        try { destroy(privateKey); } finally { privateKey = null; }
    }
}
