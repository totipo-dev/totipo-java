package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class P256Test {
    @Test
    void exactPointFormWidthRangeAndCurveAreEnforced() throws Exception {
        byte[] publicKey = fixture("fixture_public_key_hex");
        var key = P256.decode(publicKey);
        assertEquals(new BigInteger(1, Arrays.copyOfRange(publicKey, 1, 33)), key.getW().getAffineX());
        assertEquals(new BigInteger(1, Arrays.copyOfRange(publicKey, 33, 65)), key.getW().getAffineY());
        assertEquals(256, key.getParams().getCurve().getField().getFieldSize());
        assertEquals(1, key.getParams().getCofactor());
        for (int prefix : new int[]{0, 2, 3, 5, 6, 7, 255}) {
            byte[] bad = publicKey.clone();
            bad[0] = (byte) prefix;
            assertThrows(IllegalArgumentException.class, () -> P256.decode(bad));
        }
        for (int length : new int[]{0, 1, 33, 64, 66, 100}) {
            assertThrows(IllegalArgumentException.class, () -> P256.decode(Arrays.copyOf(publicKey, length)));
        }
        var p = ((ECFieldFp) key.getParams().getCurve().getField()).getP();
        for (int coordinate : new int[]{1, 33}) {
            byte[] bad = publicKey.clone();
            putCoordinate(bad, coordinate, p);
            assertThrows(IllegalArgumentException.class, () -> P256.decode(bad));
            Arrays.fill(bad, coordinate, coordinate + 32, (byte) 0xff);
            assertThrows(IllegalArgumentException.class, () -> P256.decode(bad));
        }
        byte[] offCurve = publicKey.clone();
        offCurve[64] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> P256.decode(offCurve));
        byte[] zero = new byte[65];
        zero[0] = 4;
        assertThrows(IllegalArgumentException.class, () -> P256.decode(zero));
    }

    @Test
    void suppliedSignatureFailsWithChangedMessageSignatureOrValidKey() throws Exception {
        byte[] key = fixture("fixture_public_key_hex");
        byte[] message = fixture("signature_input_hex");
        byte[] signature = fixture("signature_der_hex");
        assertTrue(P256.verify(key, message, signature));
        message[message.length - 1] ^= 1;
        assertFalse(P256.verify(key, message, signature));
        message[message.length - 1] ^= 1;
        signature[signature.length - 1] ^= 1;
        assertFalse(P256.verify(key, message, signature));
        signature[signature.length - 1] ^= 1;
        // Negating the supplied public point gives a different deterministic valid key.
        var decoded = P256.decode(key);
        var p = ((ECFieldFp) decoded.getParams().getCurve().getField()).getP();
        byte[] wrongKey = key.clone();
        putCoordinate(wrongKey, 33, p.subtract(decoded.getW().getAffineY()));
        assertNotNull(P256.decode(wrongKey));
        assertFalse(P256.verify(wrongKey, message, signature));
        assertFalse(P256.verify(key, message, new byte[0]));
        assertFalse(P256.verify(key, message, new byte[72]));
        assertFalse(P256.verify(key, message, new byte[73]));
        // Canonical DER integers r=s=1, but mathematically invalid for this message.
        assertFalse(P256.verify(key, message, HexFormat.of().parseHex("3006020101020101")));
        key[0] = 2;
        assertFalse(P256.verify(key, message, signature));
    }

    @Test
    void deviceIdHashesProtocolBytesIncludingFormWithDomainSeparation() throws Exception {
        byte[] key = fixture("fixture_public_key_hex");
        byte[] id = P256.deviceId(key);
        assertFalse(Arrays.equals(id, CryptoSupport.sha256(key)));
        assertFalse(Arrays.equals(id, CryptoSupport.sha256(P256.decode(key).getEncoded())));
        for (int i = 0; i < key.length; i++) {
            key[i] ^= 1;
            assertFalse(Arrays.equals(id, P256.deviceId(key)));
            key[i] ^= 1;
        }
        assertThrows(IllegalArgumentException.class, () -> P256.deviceId(new byte[64]));
    }

    private static byte[] fixture(String name) throws Exception {
        return CryptoVectorTest.signedCase().data().field("crypto").field(name).hex();
    }

    private static void putCoordinate(byte[] key, int offset, BigInteger coordinate) {
        byte[] encoded = coordinate.toByteArray();
        Arrays.fill(key, offset, offset + 32, (byte) 0);
        int size = Math.min(32, encoded.length);
        System.arraycopy(encoded, encoded.length - size, key, offset + 32 - size, size);
    }
}
