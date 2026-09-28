package dev.totipo.format;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.ProviderException;
import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Stateless r15 §40 calculation only; the caller must enforce credential-use policy. */
final class Totp {
    private Totp() {}

    static String generate(V1Plaintext.Credential credential, long unixSeconds) {
        return generate(credential, BigInteger.valueOf(unixSeconds));
    }

    static String generate(V1Plaintext.Credential credential, BigInteger unixSeconds) {
        // Reject invalid time/counter before obtaining a secret or starting HMAC.
        byte[] counter = encodeCounter(timeStep(unixSeconds, credential.period()));
        byte[] secret = null;
        byte[] digest = null;
        try {
            String algorithm = switch (credential.algorithm()) {
                case 1 -> "HmacSHA1";
                case 2 -> "HmacSHA256";
                case 3 -> "HmacSHA512";
                default -> throw new IllegalArgumentException("Unsupported credential algorithm");
            };
            checkDigits(credential.digits());
            secret = credential.secret();
            if (secret.length < 1 || secret.length > 128) {
                throw new IllegalArgumentException("Invalid credential secret length");
            }
            var mac = Mac.getInstance(algorithm);
            mac.init(new SecretKeySpec(secret, algorithm));
            digest = mac.doFinal(counter);
            int expectedLength = switch (credential.algorithm()) {
                case 1 -> 20;
                case 2 -> 32;
                default -> 64;
            };
            if (digest.length != expectedLength) {
                throw CryptoSupport.unavailable();
            }
            return decimalCode(truncate(digest), credential.digits());
        } catch (GeneralSecurityException | ProviderException e) {
            throw CryptoSupport.unavailable();
        } finally {
            if (secret != null) Arrays.fill(secret, (byte) 0);
            Arrays.fill(counter, (byte) 0);
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }

    static BigInteger timeStep(BigInteger unixSeconds, long period) {
        if (unixSeconds.signum() < 0) {
            throw new IllegalArgumentException("Unix seconds must be non-negative");
        }
        if (period < 1 || period > 0xffff_ffffL) {
            throw new IllegalArgumentException("Invalid credential period");
        }
        BigInteger counter = unixSeconds.divide(BigInteger.valueOf(period));
        if (counter.bitLength() > 64) {
            throw new IllegalArgumentException("TOTP counter exceeds unsigned u64");
        }
        return counter;
    }

    static byte[] encodeCounter(BigInteger counter) {
        if (counter.signum() < 0 || counter.bitLength() > 64) {
            throw new IllegalArgumentException("TOTP counter outside unsigned u64");
        }
        byte[] bytes = new byte[8];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = counter.shiftRight((7 - i) * 8).byteValue();
        }
        return bytes;
    }

    /** RFC 4226 §5.3; RFC 6238 uses the final digest byte for every algorithm. */
    static int truncate(byte[] digest) {
        if (digest.length != 20 && digest.length != 32 && digest.length != 64) {
            throw CryptoSupport.unavailable();
        }
        int offset = digest[digest.length - 1] & 0x0f;
        // The closed digest lengths guarantee that offset + 3 is in bounds.
        return ((digest[offset] & 0x7f) << 24)
                | ((digest[offset + 1] & 0xff) << 16)
                | ((digest[offset + 2] & 0xff) << 8)
                | (digest[offset + 3] & 0xff);
    }

    static String decimalCode(int binary, int digits) {
        checkDigits(digits);
        if (binary < 0) throw new IllegalArgumentException("Invalid dynamic binary code");
        char[] code = new char[digits];
        // Taking the final DIGITS decimal places is reduction modulo 10^DIGITS.
        for (int i = digits - 1; i >= 0; i--) {
            code[i] = (char) ('0' + binary % 10);
            binary /= 10;
        }
        return new String(code);
    }

    private static void checkDigits(int digits) {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("Unsupported credential digits");
        }
    }
}
