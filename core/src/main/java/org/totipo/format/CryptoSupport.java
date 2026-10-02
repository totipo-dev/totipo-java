package org.totipo.format;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Operation-local JCA primitives and the v1 key hierarchy. */
final class CryptoSupport {
    private CryptoSupport() {}

    static byte[] ascii(String literal) {
        return literal.getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] sha256(byte[]... parts) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return digest.digest();
        } catch (GeneralSecurityException e) {
            throw unavailable();
        }
    }

    static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] part : parts) {
                mac.update(part);
            }
            return mac.doFinal();
        } catch (GeneralSecurityException e) {
            throw unavailable();
        }
    }

    /** HKDF-Extract with the protocol's explicit 32-zero-byte salt. */
    static byte[] extract(byte[] root) {
        if (root.length != 32) {
            throw new IllegalArgumentException("Root key must be 32 bytes");
        }
        return hmac(new byte[32], root);
    }

    /** RFC HKDF expansion; all protocol uses request 32 bytes. */
    static byte[] expand(byte[] prk, byte[] info, int length) {
        if (prk.length != 32 || length < 0 || length > 255 * 32) {
            throw new IllegalArgumentException("Invalid HKDF parameters");
        }
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        try {
            for (int offset = 0, counter = 1; offset < length; counter++) {
                byte[] next = hmac(prk, previous, info, new byte[]{(byte) counter});
                Arrays.fill(previous, (byte) 0);
                previous = next;
                int count = Math.min(32, length - offset);
                System.arraycopy(previous, 0, output, offset, count);
                offset += count;
            }
            return output;
        } finally {
            Arrays.fill(previous, (byte) 0);
        }
    }

    static byte[] idKey(byte[] prk) {
        return expand(prk, ascii("totipo/v1/object-id"), 32);
    }

    static byte[] objectRoot(byte[] prk) {
        return expand(prk, ascii("totipo/v1/object-key-root"), 32);
    }

    static byte[] vaultFingerprint(byte[] root) {
        if (root.length != 32) {
            throw new IllegalArgumentException("Root key must be 32 bytes");
        }
        return hmac(root, ascii("totipo/v1/vault-fingerprint"));
    }

    static byte[] objectKey(byte[] objectRoot, ObjectId id) {
        return expand(objectRoot, join(ascii("totipo/v1/object-key"), id.bytes()), 32);
    }

    static byte[] join(byte[]... parts) {
        int size = 0;
        for (byte[] part : parts) {
            size = Math.addExact(size, part.length);
        }
        byte[] result = new byte[size];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    static IllegalStateException unavailable() {
        // Configuration failures are not hostile-input outcomes; do not echo key material.
        return new IllegalStateException("Required JCA cryptographic operation unavailable");
    }
}
