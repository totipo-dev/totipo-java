package dev.totipo.format;

import java.io.IOException;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Objects;

/** In-memory contract fake, NOT evidence of crash durability. Private keys never
 * cross the production SPI. Each open returns an independently closeable handle. */
final class FakeDeviceKeyStore implements DeviceProvenanceKeyStore {
    enum Fault { NONE, LOAD_IO, LOAD_INVALID, BEFORE_COMMIT, AFTER_COMMIT, COLLISION }
    enum SignFault { NONE, EMPTY, OVERSIZED, MALFORMED, WRONG_KEY, THROW, NULL, MUTATE }
    private KeyPair pair;
    private KeyPair wrongPair;
    byte[] binding, publicOverride;
    byte[] createdBindingOverride, lastMessageDigest;
    boolean nullPublicKey, nullCreateResult, throwClose;
    Fault fault = Fault.NONE;
    SignFault signFault = SignFault.NONE;
    int opens, creates, signs, closes;
    boolean closed;

    static KeyPair generate() throws GeneralSecurityException {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }
    void seed(byte[] binding) throws GeneralSecurityException {
        pair = generate(); wrongPair = generate(); this.binding = binding.clone();
    }
    private void requireOpen() { if (closed) { throw new IllegalStateException("Store closed"); } }
    @Override public DeviceProvenanceKey openExisting() throws IOException, GeneralSecurityException {
        requireOpen(); opens++;
        if (fault == Fault.LOAD_IO) { throw new IOException("Injected load failure"); }
        if (fault == Fault.LOAD_INVALID) { throw new GeneralSecurityException("Injected corruption"); }
        return pair == null ? null : new Handle();
    }
    @Override public DeviceProvenanceKey createDurably(byte[] requested) throws IOException, GeneralSecurityException {
        Objects.requireNonNull(requested);
        if (requested.length != 32) { throw new IllegalArgumentException("Binding width"); }
        requireOpen(); creates++;
        if (pair != null) { throw new IOException("Exists"); }
        if (fault == Fault.BEFORE_COMMIT) { throw new IOException("Before commit"); }
        seed(requested);
        if (createdBindingOverride != null) { binding = createdBindingOverride.clone(); }
        if (fault == Fault.AFTER_COMMIT || fault == Fault.COLLISION) {
            throw new IOException("Ambiguous commit or competing creator");
        }
        return nullCreateResult ? null : new Handle();
    }
    @Override public void close() { closed = true; }
    void reopen() { closed = false; }

    private final class Handle implements DeviceProvenanceKey {
        private boolean released;
        private void live() { if (released) { throw new IllegalStateException("Handle closed"); } }
        @Override public byte[] vaultBinding() { live(); return binding == null ? null : binding.clone(); }
        @Override public byte[] publicKeyX963() {
            live();
            if (nullPublicKey) { return null; }
            return publicOverride == null ? P256.encode((ECPublicKey) pair.getPublic()) : publicOverride.clone();
        }
        @Override public byte[] signSha256Ecdsa(byte[] message) throws GeneralSecurityException {
            Objects.requireNonNull(message); live(); signs++;
            lastMessageDigest = CryptoSupport.sha256(message);
            switch (signFault) {
                case EMPTY: return new byte[0];
                case OVERSIZED: return new byte[73];
                case MALFORMED: return new byte[]{0x30, 0};
                case THROW: throw new GeneralSecurityException("Injected signer failure");
                case NULL: return null;
                case MUTATE: message[0] ^= 1; break;
                default: break;
            }
            var signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign((signFault == SignFault.WRONG_KEY ? wrongPair : pair).getPrivate());
            signature.update(message);
            return signature.sign();
        }
        @Override public void close() {
            if (!released) { closes++; released = true; }
            if (throwClose) { throw new IllegalStateException("Injected close failure"); }
        }
        @Override public String toString() { return "TestDeviceKey[redacted]"; }
    }
}
