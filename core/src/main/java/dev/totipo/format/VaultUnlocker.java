package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Read-only r16 recovery. Callers must not mutate borrowed passwords during a call. */
final class VaultUnlocker {
    private final Argon2idKdf kdf;

    VaultUnlocker() { this(new BouncyCastleArgon2idKdf()); }

    VaultUnlocker(Argon2idKdf kdf) { this.kdf = Objects.requireNonNull(kdf); }

    /** Borrows password bytes for this call only; never retains or clears the caller's array. */
    VaultUnlockResult unlock(byte[] record, byte[] password) {
        var bootstrap = VaultBootstrap.parse(record);
        if (bootstrap == null) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.INVALID_FORMAT);
        }
        if (!PasswordBytes.valid(password)) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.INVALID_PASSWORD_INPUT);
        }
        return unwrap(bootstrap, password);
    }

    /** Borrows caller characters; clears the owned strict UTF-8 encoding after use. */
    VaultUnlockResult unlock(byte[] record, char[] password) {
        var bootstrap = VaultBootstrap.parse(record);
        if (bootstrap == null) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.INVALID_FORMAT);
        }
        byte[] encoded = PasswordBytes.encode(password);
        if (encoded == null) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.INVALID_PASSWORD_INPUT);
        }
        try {
            return unwrap(bootstrap, encoded);
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private VaultUnlockResult unwrap(VaultBootstrap bootstrap, byte[] password) {
        byte[] key = null;
        byte[] root = null;
        byte[] salt = bootstrap.salt();
        try {
            key = kdf.derive(password, salt);
            if (key.length != 32) {
                throw new IllegalStateException("KDF returned an invalid key length");
            }
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(128, bootstrap.nonce()));
            cipher.updateAAD(bootstrap.header());
            root = cipher.doFinal(bootstrap.wrappedRootAndTag());
            if (root.length != 32) {
                throw new IllegalStateException("Unexpected authenticated root length");
            }
            return VaultUnlockResult.unlocked(root);
        } catch (AEADBadTagException e) {
            return VaultUnlockResult.failure(VaultUnlockResult.Status.AUTHENTICATION_FAILED);
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.unavailable();
        } finally {
            Arrays.fill(salt, (byte) 0);
            if (key != null) {
                Arrays.fill(key, (byte) 0);
            }
            if (root != null) {
                Arrays.fill(root, (byte) 0);
            }
        }
    }
}
