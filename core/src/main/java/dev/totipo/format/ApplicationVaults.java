package dev.totipo.format;

import dev.totipo.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/** Provider bridge, not the ordinary application entry point. Owns transferred stores on all paths.
 * Publication acknowledgements must establish configured-store durability, including exact-existing
 * objects after uncertain installation. The NIO application adapter adds the needed barriers. */
public final class ApplicationVaults {
    private ApplicationVaults() { }

    public static OpenResult open(VaultBootstrapReplacementStorage bootstrap, DiscoverySource discovery,
                                  V1ObjectPublicationStore publication, char[] password) {
        Objects.requireNonNull(bootstrap); Objects.requireNonNull(discovery); Objects.requireNonNull(publication);
        boolean transferred = false;
        byte[] encoded = null;
        try {
            encoded = password(password);
            try (var result = new VaultLifecycle().open(bootstrap, encoded)) {
                if (result.status() == VaultUnlockResult.Status.UNLOCKED) {
                    byte[] root = result.root();
                    try {
                        var session = new ApplicationSession(root, bootstrap, discovery, publication);
                        transferred = true;
                        return new OpenResult.Opened(session);
                    } finally { wipe(root); }
                }
                return switch (result.status()) {
                    case ABSENT -> new OpenResult.Absent();
                    case UNAVAILABLE -> new OpenResult.Unavailable();
                    case INVALID_FORMAT -> new OpenResult.InvalidVault();
                    case AUTHENTICATION_FAILED -> new OpenResult.AuthenticationFailed();
                    default -> throw new IllegalArgumentException("Invalid password input");
                };
            }
        } finally { wipe(encoded); if (!transferred) { cleanup(publication); cleanup(bootstrap); } }
    }

    public static CreateVaultResult create(VaultBootstrapReplacementStorage bootstrap, DiscoverySource discovery,
                                           V1ObjectPublicationStore publication, char[] password) {
        Objects.requireNonNull(bootstrap); Objects.requireNonNull(discovery); Objects.requireNonNull(publication);
        byte[] encoded = null, root = new byte[32], salt = new byte[16], nonce = new byte[12];
        byte[] candidate = null;
        boolean attempted = false, transferred = false;
        VaultBootstrapStorage.StagedBootstrap stage = null;
        try {
            encoded = password(password);
            try (var existing = bootstrap.openCanonicalRead()) {
                if (existing != null) return new CreateVaultResult.AlreadyExists();
            }
            var entropy = new EntropySource.Jdk();
            entropy.fill(root); entropy.fill(salt); entropy.fill(nonce);
            candidate = new VaultBootstrapWriter().encode(encoded, root, salt, nonce);
            if (!valid(candidate, encoded, root)) return new CreateVaultResult.Failed();
            stage = bootstrap.stageInitial(candidate);
            if (!validStage(stage.openRead(), candidate, encoded, root)) return new CreateVaultResult.Failed();
            attempted = true;
            stage.installInitialDurably();
            var session = new ApplicationSession(root, bootstrap, discovery, publication);
            transferred = true;
            return new CreateVaultResult.Created(session);
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return attempted ? new CreateVaultResult.Uncertain() : new CreateVaultResult.Failed();
        } catch (RuntimeException e) {
            if (attempted) return new CreateVaultResult.Uncertain();
            throw e;
        } finally {
            cleanup(stage); wipe(encoded); wipe(root); wipe(salt); wipe(nonce); wipe(candidate);
            if (!transferred) { cleanup(publication); cleanup(bootstrap); }
        }
    }

    static PasswordChangeResult change(VaultBootstrapReplacementStorage storage, byte[] expectedRoot,
                                        char[] currentPassword, char[] newPassword) {
        byte[] current = password(currentPassword), replacement = null;
        byte[] base = null, candidate = null, salt = new byte[16], nonce = new byte[12];
        VaultBootstrapReplacementStorage.StagedReplacement stage = null;
        boolean attempted = false;
        try {
            replacement = password(newPassword);
            base = read(storage.openCanonicalRead());
            if (base == null) return PasswordChangeResult.FAILED;
            try (var opened = new VaultUnlocker().unlock(base, current)) {
                if (opened.status() == VaultUnlockResult.Status.AUTHENTICATION_FAILED)
                    return PasswordChangeResult.AUTHENTICATION_FAILED;
                if (opened.status() != VaultUnlockResult.Status.UNLOCKED) return PasswordChangeResult.FAILED;
                byte[] root = opened.root();
                try { if (!MessageDigest.isEqual(root, expectedRoot)) return PasswordChangeResult.STALE; }
                finally { wipe(root); }
            }
            var entropy = new EntropySource.Jdk(); entropy.fill(salt); entropy.fill(nonce);
            candidate = new VaultBootstrapWriter().encode(replacement, expectedRoot, salt, nonce);
            if (!valid(candidate, replacement, expectedRoot)) return PasswordChangeResult.FAILED;
            stage = storage.stageReplacement(candidate);
            if (!validStage(stage.openRead(), candidate, replacement, expectedRoot)) return PasswordChangeResult.FAILED;
            byte[] now = read(storage.openCanonicalRead());
            try {
                if (now == null) return PasswordChangeResult.FAILED;
                if (!Arrays.equals(base, now)) return PasswordChangeResult.STALE;
            }
            finally { wipe(now); }
            attempted = true;
            stage.replaceCanonicalDurably();
            return PasswordChangeResult.CHANGED;
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return attempted ? PasswordChangeResult.UNCERTAIN : PasswordChangeResult.FAILED;
        } catch (RuntimeException e) {
            if (attempted) return PasswordChangeResult.UNCERTAIN;
            throw e;
        } finally {
            cleanup(stage); wipe(current); wipe(replacement); wipe(base); wipe(candidate); wipe(salt); wipe(nonce);
        }
    }
    private static boolean validStage(InputStream stream, byte[] candidate, byte[] password, byte[] root) throws IOException {
        byte[] staged = read(stream);
        try { return Arrays.equals(candidate, staged) && valid(staged, password, root); }
        finally { wipe(staged); }
    }
    private static boolean valid(byte[] bytes, byte[] password, byte[] root) {
        try (var result = new VaultUnlocker().unlock(bytes, password)) {
            if (result.status() != VaultUnlockResult.Status.UNLOCKED) return false;
            byte[] recovered = result.root();
            try { return MessageDigest.isEqual(root, recovered); } finally { wipe(recovered); }
        }
    }
    /** Null preserves absence; any present record must have the exact protocol length. */
    private static byte[] read(InputStream stream) throws IOException {
        if (stream == null) return null;
        try (stream) {
            byte[] bytes = stream.readNBytes(VaultBootstrap.RECORD_BYTES + 1);
            if (bytes.length != VaultBootstrap.RECORD_BYTES) {
                wipe(bytes);
                throw new IOException("Invalid VAULT record length");
            }
            return bytes;
        }
    }
    static byte[] password(char[] password) {
        byte[] encoded = PasswordBytes.encode(Objects.requireNonNull(password));
        if (encoded == null) throw new IllegalArgumentException("Invalid password input");
        return encoded;
    }
    static void wipe(byte[] bytes) { if (bytes != null) Arrays.fill(bytes, (byte) 0); }
    static void cleanup(AutoCloseable resource) {
        if (resource != null) try { resource.close(); } catch (Exception ignored) { /* Best effort cleanup. */ }
    }
}
