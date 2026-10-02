package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;

class CryptoSupportTest {
    @Test
    void hkdfExtractAndExpandCrossBlockBoundariesWithBinaryCounter() throws Exception {
        byte[] root = EnvelopeTestBytes.fixture().data().field("root_hex").hex();
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(new byte[32], "HmacSHA256"));
        byte[] prk = mac.doFinal(root);
        assertArrayEquals(prk, CryptoSupport.extract(root));
        byte[] info = {0, (byte) 0xff, 0x41};
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        mac.update(info);
        byte[] first = mac.doFinal(new byte[]{1});
        mac.update(first);
        mac.update(info);
        byte[] second = mac.doFinal(new byte[]{2});
        byte[] both = new byte[64];
        System.arraycopy(first, 0, both, 0, 32);
        System.arraycopy(second, 0, both, 32, 32);
        for (int size : new int[]{0, 1, 31, 32, 33, 63, 64}) {
            assertArrayEquals(Arrays.copyOf(both, size), CryptoSupport.expand(prk, info, size));
        }
        // The last counter is binary 0xff, not a signed integer encoding or ASCII.
        byte[] previous = new byte[0];
        byte[] expected = new byte[255 * 32];
        for (int counter = 1; counter <= 255; counter++) {
            mac.update(previous);
            mac.update(info);
            previous = mac.doFinal(new byte[]{(byte) counter});
            System.arraycopy(previous, 0, expected, (counter - 1) * 32, 32);
        }
        assertArrayEquals(expected, CryptoSupport.expand(prk, info, expected.length));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.expand(prk, info, 8161));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.expand(prk, info, -1));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.expand(new byte[31], info, 32));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.extract(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.extract(new byte[33]));
    }

    @Test
    void fingerprintUsesDirectRootHmacAndExactDomain() throws Exception {
        byte[] root = new byte[32];
        for (int i = 0; i < root.length; i++) { root[i] = (byte) i; }
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(root, "HmacSHA256"));
        byte[] expected = mac.doFinal("totipo/v1/vault-fingerprint"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        assertArrayEquals(expected, CryptoSupport.vaultFingerprint(root));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.vaultFingerprint(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> CryptoSupport.vaultFingerprint(new byte[33]));
    }

    @Test
    void keyedIdentityOwnsBytesAndChangesWithEachSemanticByte() throws Exception {
        var v = EnvelopeTestBytes.fixture();
        var c = v.data().field("crypto");
        byte[] key = c.field("id_key_hex").hex();
        byte[] semantic = v.semanticBytes();
        var id = ObjectId.compute(key, semantic);
        assertEquals(c.field("object_id").string(), id.filename());
        assertEquals(id, ObjectId.fromFilename(id.filename()));
        assertEquals(id.hashCode(), ObjectId.fromFilename(id.filename()).hashCode());
        for (int i = 0; i < semantic.length; i++) {
            semantic[i] ^= 1;
            assertNotEquals(id, ObjectId.compute(key, semantic));
            semantic[i] ^= 1;
        }
        byte[] raw = id.bytes();
        var owned = new ObjectId(raw);
        raw[0] ^= 1;
        owned.bytes()[0] ^= 1;
        Arrays.fill(key, (byte) 0);
        Arrays.fill(semantic, (byte) 0);
        assertEquals(id, owned);
        assertEquals(c.field("object_id").string(), owned.filename());
        assertThrows(IllegalArgumentException.class, () -> new ObjectId(new byte[31]));
        assertThrows(IllegalArgumentException.class, () -> new ObjectId(new byte[33]));
    }
}
