package dev.totipo.format;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

import static dev.totipo.format.DeviceIdentityResult.Status.*;

/** Portable, synchronous custody orchestration. Borrows validated local replay and
 * the caller-owned store. No root, bootstrap, discovery or publication capability.
 * Caller must keep the established configuration stable while using a result. */
final class DeviceIdentityLifecycle {
    private DeviceIdentityLifecycle() {}

    static DeviceIdentityResult loadExisting(SecurityMemoryJournal.Replay replay, DeviceProvenanceKeyStore store) {
        return operate(replay, store, false);
    }
    static DeviceIdentityResult createNew(SecurityMemoryJournal.Replay replay, DeviceProvenanceKeyStore store) {
        return operate(replay, store, true);
    }
    private static DeviceIdentityResult operate(SecurityMemoryJournal.Replay replay,
                                               DeviceProvenanceKeyStore store, boolean create) {
        Objects.requireNonNull(replay);
        Objects.requireNonNull(store);
        switch (replay.status()) {
            case ABSENT: return DeviceIdentityResult.failure(LOCAL_SECURITY_MEMORY_MISSING);
            case CORRUPT, UNSUPPORTED_LOCAL_FORMAT: return DeviceIdentityResult.failure(LOCAL_SECURITY_MEMORY_INVALID);
            case INCOMPLETE_TAIL: return DeviceIdentityResult.failure(LOCAL_TAIL_REPAIR_REQUIRED);
            case CLEAN: break;
        }
        if (replay.establishment().phase() != LocalEstablishment.Phase.ESTABLISHED) {
            return DeviceIdentityResult.failure(LOCAL_STATE_NOT_ESTABLISHED);
        }
        byte[] binding = replay.establishment().binding().bytes();
        DeviceProvenanceKey key;
        try { key = store.openExisting(); }
        catch (IOException e) { return DeviceIdentityResult.failure(KEY_STORAGE_UNAVAILABLE); }
        catch (GeneralSecurityException | RuntimeException e) { return DeviceIdentityResult.failure(KEY_MATERIAL_INVALID); }
        if (create) {
            if (key != null) {
                closeFailed(key);
                return DeviceIdentityResult.failure(KEY_ALREADY_EXISTS);
            }
            try { key = store.createDurably(binding.clone()); }
            catch (IOException | GeneralSecurityException | RuntimeException e) {
                return DeviceIdentityResult.failure(KEY_CREATION_INCOMPLETE);
            }
            if (key == null) { return DeviceIdentityResult.failure(KEY_CREATION_INCOMPLETE); }
        } else if (key == null) { return DeviceIdentityResult.failure(ABSENT); }
        DeviceIdentityResult result = null;
        boolean transferred = false;
        try {
            byte[] storedBinding = key.vaultBinding();
            if (storedBinding == null || storedBinding.length != 32) {
                return DeviceIdentityResult.failure(KEY_MATERIAL_INVALID);
            }
            if (!MessageDigest.isEqual(binding, storedBinding)) {
                return DeviceIdentityResult.failure(KEY_BINDING_MISMATCH);
            }
            byte[] publicKey = Objects.requireNonNull(key.publicKeyX963()).clone();
            P256.decode(publicKey);
            result = DeviceIdentityResult.bound(create ? CREATED_BOUND : AVAILABLE_BOUND, key, binding, publicKey);
            byte[] message = CryptoSupport.join(CryptoSupport.ascii("totipo-java/device-key-self-test/v1"),
                    new byte[]{0}, binding, publicKey);
            try { result.signSha256Ecdsa(message); }
            finally { Arrays.fill(message, (byte) 0); }
            transferred = true;
            return result;
        } catch (GeneralSecurityException | RuntimeException e) {
            return DeviceIdentityResult.failure(KEY_MATERIAL_INVALID);
        } finally {
            if (!transferred) {
                if (result != null) {
                    try { result.close(); } catch (RuntimeException ignored) { /* Already unusable. */ }
                } else { closeFailed(key); }
            }
        }
    }
    private static void closeFailed(DeviceProvenanceKey key) {
        try { key.close(); } catch (RuntimeException ignored) { /* Never expose failed handle. */ }
    }
}
