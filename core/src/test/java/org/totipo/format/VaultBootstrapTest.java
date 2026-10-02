package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import org.totipo.conformance.VectorCaseLoader;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class VaultBootstrapTest {
    static byte[] record() throws Exception {
        return VectorCaseLoader.bootstrapCases().get(0).data().field("bootstrap").field("record_hex").hex();
    }

    @Test
    void everyShortLengthAndOversizedInputsRejectWithoutKdf() throws Exception {
        byte[] valid = record();
        for (int length = 0; length < 87; length++) {
            rejects(Arrays.copyOf(valid, length), VaultUnlockResult.Status.INVALID_FORMAT);
        }
        for (int length : new int[]{88, 4096}) {
            rejects(Arrays.copyOf(valid, length), VaultUnlockResult.Status.INVALID_FORMAT);
        }
        assertNotNull(VaultBootstrap.parse(valid));
    }

    @Test
    void everyMagicByteAndUnsupportedVersionRejectWithoutKdf() throws Exception {
        for (int i = 0; i < 10; i++) {
            byte[] bytes = record();
            bytes[i] ^= 1;
            rejects(bytes, VaultUnlockResult.Status.INVALID_FORMAT);
        }
        for (int version : new int[]{0, 2, 255}) {
            byte[] bytes = record();
            bytes[10] = (byte) version;
            rejects(bytes, VaultUnlockResult.Status.INVALID_FORMAT);
        }
    }

    private static void rejects(byte[] record, VaultUnlockResult.Status status) {
        var unlocker = forbiddenKdf();
        assertNull(VaultBootstrap.parse(record));
        assertEquals(status, unlocker.unlock(record, new byte[0]).status());
        assertEquals(status, unlocker.unlock(record, new char[0]).status());
    }

    private static VaultUnlocker forbiddenKdf() {
        return new VaultUnlocker((password, salt) -> { throw new AssertionError("KDF must not run"); });
    }

    @Test
    void invalidPasswordsNeverInvokeKdf() throws Exception {
        var unlocker = forbiddenKdf();
        for (String hex : new String[]{"ff", "80", "c241", "e282", "c0af", "eda080", "f4908080"}) {
            var result = unlocker.unlock(record(), HexFormat.of().parseHex(hex));
            assertEquals(VaultUnlockResult.Status.INVALID_PASSWORD_INPUT, result.status());
            assertNull(result.root());
        }
        assertEquals(VaultUnlockResult.Status.INVALID_PASSWORD_INPUT,
                unlocker.unlock(record(), new byte[1025]).status());
        for (char[] chars : new char[][]{{'\ud800'}, {'\udc00'}, new char[1025]}) {
            assertEquals(VaultUnlockResult.Status.INVALID_PASSWORD_INPUT, unlocker.unlock(record(), chars).status());
        }
    }

    @Test
    void bootstrapDefensivelyOwnsExactlyOneRecord() throws Exception {
        byte[] bytes = record();
        var parsed = VaultBootstrap.parse(bytes);
        byte[] salt = parsed.salt();
        byte[] nonce = parsed.nonce();
        byte[] header = parsed.header();
        byte[] encrypted = parsed.wrappedRootAndTag();
        Arrays.fill(bytes, (byte) 0);
        Arrays.fill(parsed.salt(), (byte) 0);
        Arrays.fill(parsed.nonce(), (byte) 0);
        Arrays.fill(parsed.header(), (byte) 0);
        Arrays.fill(parsed.wrappedRootAndTag(), (byte) 0);
        assertArrayEquals(salt, parsed.salt());
        assertArrayEquals(nonce, parsed.nonce());
        assertArrayEquals(header, parsed.header());
        assertArrayEquals(encrypted, parsed.wrappedRootAndTag());
    }
}
