package org.totipo.format;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/** Internal v1 canonical-bootstrap workflows. Borrows storage and passwords synchronously.
 * No TOKEN observation, application recognition policy, or persistent lifecycle state.
 * Durable acknowledgements concern only the configured local store, not its freshness. */
final class VaultLifecycle {
    // FAILED includes ambiguous persistence; it never proves canonical bytes are unchanged.
    enum PasswordChangeResult { SUCCESS, STALE, FAILED }
    enum CreationStatus { CREATED, FAILED }

    /** Owns the successful root through the existing closeable unwrap result. */
    static final class CreationResult implements AutoCloseable {
        private final VaultUnlockResult unlocked;
        private CreationResult(VaultUnlockResult unlocked) { this.unlocked = unlocked; }
        CreationStatus status() { return unlocked == null ? CreationStatus.FAILED : CreationStatus.CREATED; }
        byte[] root() { return requireCreated().root(); }
        byte[] fingerprint() { return requireCreated().fingerprint(); }
        private VaultUnlockResult requireCreated() {
            if (unlocked == null) throw new IllegalStateException("No created vault");
            return unlocked;
        }
        @Override public void close() { if (unlocked != null) unlocked.close(); }
        @Override public String toString() { return "CreationResult[" + status() + "]"; }
    }

    private final VaultBootstrapWriter writer;
    private final VaultUnlocker unlocker;
    private final EntropySource entropy;

    VaultLifecycle() { this(new VaultBootstrapWriter(), new VaultUnlocker(), new EntropySource.Jdk()); }
    VaultLifecycle(VaultBootstrapWriter writer, VaultUnlocker unlocker, EntropySource entropy) {
        this.writer = Objects.requireNonNull(writer);
        this.unlocker = Objects.requireNonNull(unlocker);
        this.entropy = Objects.requireNonNull(entropy);
    }

    /** Successful result owns the recovered root; no remembered fingerprint is required. */
    VaultUnlockResult open(VaultBootstrapStorage storage, byte[] password) {
        byte[] canonical = null;
        try {
            canonical = read(storage.openCanonicalRead());
            return canonical == null ? VaultUnlockResult.failure(VaultUnlockResult.Status.ABSENT)
                    : unlocker.unlock(canonical, password);
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.UNAVAILABLE);
        } finally { wipe(canonical); }
    }

    CreationResult createNew(VaultBootstrapStorage storage, byte[] password) {
        byte[] root = null, salt = null, nonce = null, candidate = null;
        VaultBootstrapStorage.StagedBootstrap stage = null;
        try {
            // Presence, including a malformed or unreadable entry, is never permission to create.
            try (var observed = storage.openCanonicalRead()) {
                if (observed != null) return new CreationResult(null);
            }
            if (!PasswordBytes.valid(password)) return new CreationResult(null);
            root = new byte[32]; salt = new byte[16]; nonce = new byte[12];
            entropy.fill(root); entropy.fill(salt); entropy.fill(nonce);
            candidate = writer.encode(password, root, salt, nonce);
            if (!validates(candidate, password, root)) return new CreationResult(null);
            stage = storage.stageInitial(candidate);
            if (!validatesStage(stage.openRead(), candidate, password, root)) return new CreationResult(null);
            stage.installInitialDurably(); // Exactly one no-replace attempt; ambiguity is failure.
            return new CreationResult(VaultUnlockResult.unlocked(root));
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return new CreationResult(null);
        } finally {
            cleanup(stage);
            wipe(root); wipe(salt); wipe(nonce); wipe(candidate);
        }
    }

    PasswordChangeResult changePassword(VaultBootstrapReplacementStorage storage,
                                        byte[] currentPassword, byte[] newPassword) {
        byte[] base = null, root = null, salt = null, nonce = null, candidate = null;
        VaultBootstrapReplacementStorage.StagedReplacement stage = null;
        try {
            base = read(storage.openCanonicalRead());
            if (base == null) return PasswordChangeResult.FAILED;
            try (var opened = unlocker.unlock(base, currentPassword)) {
                if (opened.status() != VaultUnlockResult.Status.UNLOCKED || !PasswordBytes.valid(newPassword))
                    return PasswordChangeResult.FAILED;
                root = opened.root();
            }
            salt = new byte[16]; nonce = new byte[12];
            entropy.fill(salt); entropy.fill(nonce); // Never draw a new root during rewrap.
            candidate = writer.encode(newPassword, root, salt, nonce);
            if (!validates(candidate, newPassword, root)) return PasswordChangeResult.FAILED;
            stage = storage.stageReplacement(candidate);
            if (!validatesStage(stage.openRead(), candidate, newPassword, root)) return PasswordChangeResult.FAILED;
            byte[] current = read(storage.openCanonicalRead());
            try {
                if (current == null) return PasswordChangeResult.FAILED;
                if (!Arrays.equals(base, current)) return PasswordChangeResult.STALE;
            } finally { wipe(current); }
            // Compare-before-replace, not CAS: v1 accepts the remaining observation/move race.
            stage.replaceCanonicalDurably();
            // v1 success is the backend's durability acknowledgement; no required post-open.
            return PasswordChangeResult.SUCCESS;
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            // No retry, rollback, deletion of canonical, or inference about which wrapper won.
            return PasswordChangeResult.FAILED;
        } finally {
            cleanup(stage);
            wipe(base); wipe(root); wipe(salt); wipe(nonce); wipe(candidate);
        }
    }

    private boolean validatesStage(InputStream stream, byte[] intended, byte[] password, byte[] root)
            throws IOException {
        byte[] staged = read(stream);
        try { return Arrays.equals(intended, staged) && validates(staged, password, root); }
        finally { wipe(staged); }
    }

    private boolean validates(byte[] candidate, byte[] password, byte[] intendedRoot) {
        try (var opened = unlocker.unlock(candidate, password)) {
            if (opened.status() != VaultUnlockResult.Status.UNLOCKED) return false;
            byte[] recovered = opened.root();
            try {
                return MessageDigest.isEqual(intendedRoot, recovered)
                        && MessageDigest.isEqual(CryptoSupport.vaultFingerprint(intendedRoot), opened.fingerprint());
            } finally { wipe(recovered); }
        }
    }

    /** One extra byte distinguishes exact 87 from long; never trust an advertised size. */
    private static byte[] read(InputStream stream) throws IOException {
        if (stream == null) return null;
        try (stream) { return stream.readNBytes(88); }
    }

    private static void wipe(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
    private static void cleanup(AutoCloseable stage) {
        if (stage != null) {
            try { stage.close(); }
            catch (Exception ignored) { /* Best effort; cleanup is not a durability barrier or secure erasure. */ }
        }
    }
}
