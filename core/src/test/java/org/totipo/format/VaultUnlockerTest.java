package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import org.totipo.conformance.VectorCaseLoader;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class VaultUnlockerTest {
    @Test
    void ownedPasswordAndWrappingKeyAreClearedOnSuccessAndAuthenticationFailure() throws Exception {
        var b = VectorCaseLoader.bootstrapCases().get(0).data().field("bootstrap");
        for (boolean corrupt : new boolean[]{false, true}) {
            byte[][] borrowed = new byte[2][];
            byte[] key = b.field("wrap_key_hex").hex();
            var unlocker = new VaultUnlocker((password, salt) -> {
                borrowed[0] = password;
                borrowed[1] = salt;
                return key;
            });
            byte[] record = b.field("record_hex").hex();
            if (corrupt) { record[71] ^= 1; }
            char[] chars = {'a'};
            var result = unlocker.unlock(record, chars);
            assertEquals(corrupt ? VaultUnlockResult.Status.AUTHENTICATION_FAILED : VaultUnlockResult.Status.UNLOCKED,
                    result.status());
            assertTrue(allZero(key));
            assertTrue(allZero(borrowed[0]));
            assertTrue(allZero(borrowed[1]));
            assertArrayEquals(new char[]{'a'}, chars);
        }
    }

    @Test
    void localKdfFailuresPropagateAndTemporaryPasswordIsStillCleared() throws Exception {
        byte[][] borrowed = new byte[1][];
        var failure = new IllegalStateException("Local KDF failure");
        var unlocker = new VaultUnlocker((password, salt) -> {
            borrowed[0] = password;
            throw failure;
        });
        byte[] record = VaultBootstrapTest.record();
        assertSame(failure, assertThrows(IllegalStateException.class, () -> unlocker.unlock(record, new char[]{'a'})));
        assertTrue(allZero(borrowed[0]));
        byte[] callerBytes = {'a'};
        assertSame(failure, assertThrows(IllegalStateException.class, () -> unlocker.unlock(record, callerBytes)));
        assertArrayEquals(new byte[]{'a'}, callerBytes);
        var fatal = new LinkageError("Local linkage failure");
        var fatalUnlocker = new VaultUnlocker((password, salt) -> { throw fatal; });
        assertSame(fatal, assertThrows(LinkageError.class, () -> fatalUnlocker.unlock(record, callerBytes)));
    }

    @Test
    void incorrectKdfOutputIsLocalFailureAndIsCleared() throws Exception {
        byte[] key = new byte[31];
        Arrays.fill(key, (byte) 1);
        var unlocker = new VaultUnlocker((password, salt) -> key);
        byte[] record = VaultBootstrapTest.record();
        assertThrows(IllegalStateException.class, () -> unlocker.unlock(record, new byte[0]));
        assertTrue(allZero(key));
        assertThrows(IllegalArgumentException.class,
                () -> new BouncyCastleArgon2idKdf().derive(new byte[0], new byte[15]));
    }

    @Test
    void resultOwnsRootAndNeverPrintsIt() {
        byte[] root = new byte[32];
        Arrays.fill(root, (byte) 0x11);
        byte[] expected = root.clone();
        var result = VaultUnlockResult.unlocked(root);
        Arrays.fill(root, (byte) 0);
        Arrays.fill(result.root(), (byte) 0);
        assertTrue(Arrays.equals(expected, result.root()), "Defensive root ownership");
        byte[] fingerprint = java.util.HexFormat.of().parseHex(
                "d0303d606c66abddc195cac893262a84454ecb7a17accafff1ee305f36964bf4");
        assertArrayEquals(fingerprint, result.fingerprint());
        Arrays.fill(result.fingerprint(), (byte) 0);
        assertArrayEquals(fingerprint, result.fingerprint());
        assertEquals("VaultUnlockResult[UNLOCKED]", result.toString());
        result.close(); result.close();
        assertThrows(IllegalStateException.class, result::root);
        assertThrows(IllegalStateException.class, result::fingerprint);
        assertEquals("VaultUnlockResult[UNLOCKED]", result.toString());
        assertThrows(IllegalArgumentException.class, () -> VaultUnlockResult.unlocked(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> VaultUnlockResult.failure(VaultUnlockResult.Status.UNLOCKED));
    }

    private static boolean allZero(byte[] bytes) {
        return Arrays.equals(new byte[bytes.length], bytes);
    }
}
