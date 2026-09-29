package dev.totipo.format;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** r16 encoding for creation and rewrap. Borrows inputs for the call, retains none. */
final class VaultBootstrapWriter {
    private final Argon2idKdf kdf;
    VaultBootstrapWriter() { this(new BouncyCastleArgon2idKdf()); }
    VaultBootstrapWriter(Argon2idKdf kdf) { this.kdf = Objects.requireNonNull(kdf); }

    byte[] encode(byte[] password, byte[] root, byte[] salt, byte[] nonce) {
        if (!PasswordBytes.valid(password) || root.length != 32 || salt.length != 16 || nonce.length != 12) {
            throw new IllegalArgumentException("Invalid bootstrap inputs");
        }
        byte[] header = CryptoSupport.join(CryptoSupport.ascii("TOTIPO-VLT"), new byte[]{1}, salt, nonce);
        byte[] key = null;
        try {
            key = kdf.derive(password, salt);
            if (key.length != 32) { throw new IllegalStateException("KDF returned an invalid key length"); }
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(header);
            return CryptoSupport.join(header, cipher.doFinal(root));
        } catch (GeneralSecurityException e) {
            throw CryptoSupport.unavailable();
        } finally {
            if (key != null) { Arrays.fill(key, (byte) 0); }
        }
    }
}
