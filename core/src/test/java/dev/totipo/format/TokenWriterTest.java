package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenWriterTest {
    static TokenValue value(int status, String issuer, String account, int algorithm, int digits, long period, int secretLength) {
        byte[] secret = new byte[secretLength]; Arrays.fill(secret, (byte) 0xa5);
        return new TokenValue(status, issuer, account, new TokenValue.Credential(algorithm, digits, period, new SecurityBytes(secret, secretLength)));
    }
    static byte[] write(DeviceWriterTest.CapturingKey key, TokenValue value, byte[] time, List<ObjectId> parents) throws Exception {
        return TokenWriter.signed(DeviceWriterTest.root(), key.identity(), new byte[32], value, time, parents);
    }
    @ParameterizedTest @ValueSource(strings = {"v1.crypto.token-root.001", "v1.crypto.token-child.001"})
    void exactPinnedFixtures(String name) throws Exception {
        var fixture = ProvenanceTest.fixture(name);
        var original = V1PlaintextParser.parse(fixture.semanticBytes()).plaintext();
        var r = original.routing();
        byte[] time = java.nio.ByteBuffer.allocate(8).putLong(r.authorTime().longValue()).array();
        var key = new DeviceWriterTest.CapturingKey();
        key.fixedSignature = original.signature();
        byte[] semantic = TokenWriter.signed(ProvenanceTest.root(fixture), key.identity(), r.identity(), TokenValue.from(original.token()),
                time, r.parents().stream().map(ObjectId::new).toList());
        assertArrayEquals(fixture.semanticBytes(), semantic);
        assertArrayEquals(fixture.data().field("crypto").field("signature_input_hex").hex(), key.message);
        var object = V1EnvelopeWriter.seal(ProvenanceTest.root(fixture), semantic);
        assertEquals(fixture.data().field("crypto").field("object_id").string(), object.id().filename());
        assertArrayEquals(fixture.data().field("crypto").field("object_hex").hex(), object.bytes());
        var assertion = AssertionValidator.validate(EnvelopeReader.open(object.id().filename(), object.bytes(), ProvenanceTest.root(fixture))).object();
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion, ProvenanceTest.root(fixture), VerificationKeyMaterial.keys(DeviceWriterTest.KEY)));
        byte[] wrongRoot = ProvenanceTest.root(fixture); wrongRoot[0] ^= 1;
        assertEquals(ProvenanceStatus.REJECTED, ProvenanceEvaluator.evaluate(assertion, wrongRoot, VerificationKeyMaterial.keys(DeviceWriterTest.KEY)));
    }
    @ParameterizedTest @ValueSource(strings = {"0000000000000000", "0000000000000001", "7fffffffffffffff", "8000000000000000", "ffffffffffffffff", "0123456789abcdef"})
    void times(String hex) throws Exception {
        var value = value(2, "", "", 3, 8, 0xffffffffL, 128);
        byte[] time = DeviceWriterTest.hex(hex);
        var semantic = write(new DeviceWriterTest.CapturingKey(), value, time, List.of());
        assertTrue(TokenWriterTest.matches(V1PlaintextParser.parse(semantic).plaintext(), new byte[32], DeviceWriterTest.KEY, value, time, List.of()));
    }
    @Test void capacityAndParents() throws Exception {
        var key = new DeviceWriterTest.CapturingKey();
        var max = value(1, "a".repeat(256), "b".repeat(256), 1, 6, 30, 128);
        byte[] bytes = write(key, max, new byte[8], List.of());
        var parsed = V1PlaintextParser.parse(bytes).plaintext();
        assertEquals(855, bytes.length - parsed.signature().length + 72);
        // Independently add each TLV header/value, including the nested credential.
        assertEquals(215, 5 + 5 + 6 + 12 + 36 + 36 + 5 + 4 + 4 + 4 + 5 + 5 + 8 + 4 + 76);
        var boundary = value(1, "a".repeat(20), "b".repeat(30), 1, 6, 30, 21);
        bytes = write(key, boundary, new byte[8], DeviceWriterTest.parents(20));
        parsed = V1PlaintextParser.parse(bytes).plaintext();
        assertEquals(1006, bytes.length - parsed.signature().length + 72);
        assertEquals(DeviceWriter.canonicalParents(DeviceWriterTest.parents(20)), parsed.routing().parents().stream().map(ObjectId::new).toList());
        int calls = key.calls;
        for (int count : new int[]{21, 32, 33}) {
            assertThrows(IllegalArgumentException.class, () -> write(key, boundary, new byte[8], DeviceWriterTest.parents(count)));
        }
        assertThrows(IllegalArgumentException.class, () -> write(key, value(1, "a".repeat(20), "b".repeat(30), 1, 6, 30, 22), new byte[8], DeviceWriterTest.parents(20)));
        var parent = DeviceWriterTest.parents(1).get(0);
        assertThrows(IllegalArgumentException.class, () -> write(key, boundary, new byte[8], List.of(parent, parent)));
        assertEquals(calls, key.calls);
        write(key, boundary, new byte[8], List.of(parent));
    }
    @Test void exactNestedCredentialAndOwnership() throws Exception {
        byte[] secret = {(byte) 0x80, 1, (byte) 0xff};
        var value = new TokenValue(1, "", "", new TokenValue.Credential(2, 7, 0x12345678L, new SecurityBytes(secret, 3)));
        Arrays.fill(secret, (byte) 0); Arrays.fill(value.credential().secret().bytes(), (byte) 0);
        var key = new DeviceWriterTest.CapturingKey();
        var bytes = write(key, value, new byte[8], List.of());
        String hex = java.util.HexFormat.of().formatHex(bytes);
        assertTrue(hex.contains("01060019030100010203020001070303000412345678030400038001ff"));
        assertEquals(value, TokenValue.from(V1PlaintextParser.parse(bytes).plaintext().token()));
        assertFalse(value.toString().contains("80"));
    }
    @Test void utf8AndScalarBoundaries() throws Exception {
        for (String text : List.of("", "ASCII", "é", "e\u0301", "\u0000", "a".repeat(256), "é".repeat(128))) {
            var value = value(1, text, text, 1, 6, 1, 1);
            assertEquals(value, TokenValue.from(V1PlaintextParser.parse(write(new DeviceWriterTest.CapturingKey(), value, new byte[8], List.of())).plaintext().token()));
        }
        for (String text : List.of("a".repeat(257), "é".repeat(129), "\ud800", "\udc00")) {
            for (boolean issuer : List.of(true, false)) {
                var key = new DeviceWriterTest.CapturingKey();
                assertThrows(IllegalArgumentException.class, () -> write(key, value(1, issuer ? text : "", issuer ? "" : text, 1, 6, 30, 1), new byte[8], List.of()));
                assertEquals(0, key.calls);
            }
        }
        for (int algorithm = 1; algorithm <= 3; algorithm++) {
            for (int digits = 6; digits <= 8; digits++) {
                write(new DeviceWriterTest.CapturingKey(), value(1, "", "", algorithm, digits, 0xffffffffL, 128), new byte[8], List.of());
            }
        }
        for (var invalid : List.of(value(0,"","",1,6,30,1), value(1,"","",0,6,30,1), value(1,"","",4,6,30,1),
                value(1,"","",1,5,30,1), value(1,"","",1,9,30,1), value(1,"","",1,6,0,1), value(1,"","",1,6,0x100000000L,1),
                value(1,"","",1,6,30,0), value(1,"","",1,6,30,129))) {
            var key = new DeviceWriterTest.CapturingKey();
            assertThrows(IllegalArgumentException.class, () -> write(key, invalid, new byte[8], List.of()));
            assertEquals(0, key.calls);
        }
    }
    @ParameterizedTest @ValueSource(strings = {
        "3046022100a66c2f8a8c6740021698500a201ddb23d502ea0ce722ebda9dce3e058540b856022100f98ecf1b2da6b5c774bd2744b247439a900ac45f2b300b72e122d6a194552705",
        "30450220137afdedeae26243d061b3dbf706589b1165de539adb74cfc276c78597c33cc9022100eeae9069d4eea9510a460abd17a40715292a5aa0c31031c3ffaff4b91efdcb1a",
        "304402200d97818b0eb7b7b5a9b29e7de6733d4f2aee64684923be7c8887b0f8e811a5bd0220010400d1f63b65ad67ff43b27d47009324db70da6bf808c524c1b07d6d49a8a4"})
    void fixedValidSignatureLengthsReserveSameCapacity(String signature) throws Exception {
        // Captured once from JCA; no signature search in production or this test.
        var key = new DeviceWriterTest.CapturingKey(); key.fixedSignature = DeviceWriterTest.hex(signature);
        var candidate = value(1, "a".repeat(20), "b".repeat(30), 1, 6, 30, 21);
        byte[] semantic = write(key, candidate, new byte[8], DeviceWriterTest.parents(20));
        assertEquals(1006 - 72 + key.fixedSignature.length, semantic.length);
        var zone = java.util.TimeZone.getDefault();
        try {
            java.util.TimeZone.setDefault(java.util.TimeZone.getTimeZone("Pacific/Auckland"));
            assertArrayEquals(semantic, write(key, candidate, new byte[8], DeviceWriterTest.parents(20)));
        } finally { java.util.TimeZone.setDefault(zone); }
        assertThrows(IllegalArgumentException.class, () -> write(key,
                value(1, "a".repeat(20), "b".repeat(30), 1, 6, 30, 22), new byte[8], DeviceWriterTest.parents(20)));
        assertEquals(2, key.calls);
    }
    static boolean matches(V1Plaintext parsed, byte[] id, byte[] key, TokenValue value,
                           byte[] time, List<ObjectId> parents) {
        if (parsed == null || parsed.token() == null) { return false; }
        var r = parsed.routing();
        return r.version() == 1 && r.objectType() == 1 && Arrays.equals(r.identity(), id)
                && Arrays.equals(r.authorDeviceId(), P256.deviceId(key))
                && r.authorTime().equals(new java.math.BigInteger(1, time))
                && r.parents().stream().map(ObjectId::new).toList().equals(parents)
                && TokenValue.from(parsed.token()).equals(value);
    }
}
