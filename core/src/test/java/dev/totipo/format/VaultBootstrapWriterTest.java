package dev.totipo.format;

import org.junit.jupiter.api.Test;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class VaultBootstrapWriterTest {
    @Test void exactFormatAndRealReaderRoundTripIncludingEmptyPassword() {
        byte[] root = field(32, 3), salt = field(16, 71), nonce = field(12, 91);
        for (byte[] password : new byte[][] {new byte[0], CryptoSupport.ascii("fixed password")}) {
            byte[] encoded = new VaultBootstrapWriter().encode(password, root, salt, nonce);
            assertEquals(87, encoded.length);
            assertArrayEquals(CryptoSupport.ascii("TOTIPO-VLT"), Arrays.copyOf(encoded, 10));
            assertEquals(1, encoded[10]);
            assertArrayEquals(salt, Arrays.copyOfRange(encoded, 11, 27));
            assertArrayEquals(nonce, Arrays.copyOfRange(encoded, 27, 39));
            assertArrayEquals(CryptoSupport.join(CryptoSupport.ascii("TOTIPO-VLT"), new byte[]{1}, salt, nonce),
                    VaultBootstrap.parse(encoded).header());
            assertEquals(32, Arrays.copyOfRange(encoded, 39, 71).length);
            assertEquals(16, Arrays.copyOfRange(encoded, 71, 87).length);
            try (var result = new VaultUnlocker().unlock(encoded, password)) {
                assertEquals(VaultUnlockResult.Status.UNLOCKED, result.status());
                assertArrayEquals(root, result.root());
                assertArrayEquals(CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/vault-fingerprint")), result.fingerprint());
            }
            // Authentication by the existing reader checks exact header/AAD and tag boundaries.
            encoded[11] ^= 1;
            try (var result = new VaultUnlocker().unlock(encoded, password)) {
                assertEquals(VaultUnlockResult.Status.AUTHENTICATION_FAILED, result.status());
            }
        }
    }
    @Test void invalidWidthsAndPasswordsRejectedBeforeKdf() {
        var writer = new VaultBootstrapWriter((p,s) -> { throw new AssertionError("KDF should not run"); });
        assertThrows(IllegalArgumentException.class, () -> writer.encode(new byte[]{(byte)255}, new byte[32], new byte[16], new byte[12]));
        assertThrows(IllegalArgumentException.class, () -> writer.encode(new byte[0], new byte[31], new byte[16], new byte[12]));
        assertThrows(IllegalArgumentException.class, () -> writer.encode(new byte[0], new byte[32], new byte[15], new byte[12]));
        assertThrows(IllegalArgumentException.class, () -> writer.encode(new byte[0], new byte[32], new byte[16], new byte[11]));
    }
    @Test void productionEntropyIsJdkSecureRandom() throws Exception {
        var source = new EntropySource.Jdk();
        var field = source.getClass().getDeclaredField("random"); field.setAccessible(true);
        assertInstanceOf(java.security.SecureRandom.class, field.get(source));
    }
    @Test void writerClearsDerivedKeyEvenOnFailure() {
        byte[] key = new byte[31]; Arrays.fill(key, (byte)42);
        var writer = new VaultBootstrapWriter((p,s) -> key);
        assertThrows(IllegalStateException.class, () -> writer.encode(new byte[0], new byte[32], new byte[16], new byte[12]));
        assertArrayEquals(new byte[31], key);
    }
    static byte[] field(int size, int start) {
        byte[] b = new byte[size]; for (int i=0; i<size; i++) { b[i]=(byte)(start+i); } return b;
    }
}
