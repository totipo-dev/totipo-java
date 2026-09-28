package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.spec.ECPrivateKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DeviceWriterTest {
    static final byte[] KEY = HexFormat.of().parseHex("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    static final String UNSIGNED = "0001000101000200010200040002000000060008000000000000000002000020f4c5e2661634374eff53ec5a9abc2512f155834804db0fa9207e950d55ee4c3502010041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50202000e4669787475726520646576696365";
    static byte[] root() { byte[] r = new byte[32]; Arrays.fill(r, (byte) 0x11); return r; }
    static byte[] hex(String s) { return HexFormat.of().parseHex(s); }

    /** Captures the exact un-hashed input while delegating ECDSA to the real JCA provider. */
    static final class CapturingKey implements DeviceProvenanceKey {
        byte[] message;
        int calls;
        byte[] fixedSignature;
        Runnable afterCapture = () -> {};
        @Override public byte[] vaultBinding() { return CryptoSupport.hmac(root(), CryptoSupport.ascii("totipo/v1/local-vault-binding")); }
        @Override public byte[] publicKeyX963() { return KEY.clone(); }
        @Override public byte[] signSha256Ecdsa(byte[] input) throws java.security.GeneralSecurityException {
            message = input.clone(); calls++;
            afterCapture.run();
            if (fixedSignature != null) { return fixedSignature.clone(); }
            var key = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(BigInteger.ONE, P256.decode(KEY).getParams()));
            var signer = Signature.getInstance("SHA256withECDSA");
            signer.initSign(key); signer.update(input); return signer.sign();
        }
        @Override public void close() {}
        DeviceIdentityResult identity() {
            return DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND, this, vaultBinding(), KEY);
        }
    }
    static VectorCaseLoader.Case fixture() throws Exception {
        return VectorCaseLoader.cryptoCases().stream().filter(v -> v.id().equals("v1.crypto.device-root.001")).findFirst().orElseThrow();
    }
    static List<ObjectId> parents(int count) {
        var result = new ArrayList<ObjectId>();
        for (int i = count; i > 0; i--) { byte[] bytes = new byte[32]; bytes[0] = (byte) (i + 120); result.add(new ObjectId(bytes)); }
        return result;
    }
    @Test void exactUnsignedAndSignerInputFixtureWithRealSigning() throws Exception {
        var key = new CapturingKey();
        byte[] semantic = DeviceWriter.signed(root(), key.identity(), "Fixture device", new byte[8], List.of());
        var value = V1PlaintextParser.parse(semantic).plaintext();
        byte[] unsigned = Arrays.copyOf(semantic, semantic.length - 4 - value.signature().length);
        assertArrayEquals(hex(UNSIGNED), unsigned);
        byte[] expected = hex("746f7469706f2f76312f646576696365551bac2f3e4ad51ec59ad3b7dba4805f51e6a96bdfa736b132cecf15b6d7f156" + UNSIGNED);
        assertArrayEquals(expected, key.message);
        assertArrayEquals(fixture().data().field("crypto").field("signature_input_hex").hex(), key.message);
        assertEquals(1, key.calls);
        assertTrue(P256.verify(KEY, expected, value.signature()));
        assertFalse(P256.verify(KEY, P256.signatureInput(root(), 1, unsigned), value.signature()));
        assertFalse(P256.verify(KEY, CryptoSupport.join(CryptoSupport.ascii("totipo/v1/device"), unsigned), value.signature()));
        unsigned[unsigned.length - 1] ^= 1;
        assertFalse(P256.verifySemantic(root(), 2, unsigned, KEY, value.signature()));
        unsigned[unsigned.length - 1] ^= 1;
        byte[] other = root(); other[0] ^= 1;
        assertFalse(Arrays.equals(DeviceWriter.signatureInput(root(), unsigned), DeviceWriter.signatureInput(other, unsigned)));
        assertFalse(P256.verifySemantic(other, 2, unsigned, KEY, value.signature()));
        // Also sign the wrong inputs themselves: none verifies against the DEVICE input.
        for (byte[] wrong : List.of(P256.signatureInput(root(), 1, unsigned),
                CryptoSupport.join(CryptoSupport.ascii("totipo/v1/device"), unsigned),
                DeviceWriter.signatureInput(other, unsigned))) {
            assertFalse(P256.verify(KEY, expected, key.signSha256Ecdsa(wrong)));
        }
        unsigned[unsigned.length - 1] ^= 1;
        assertFalse(P256.verify(KEY, expected, key.signSha256Ecdsa(DeviceWriter.signatureInput(root(), unsigned))));
    }
    @ParameterizedTest @ValueSource(strings = {"0000000000000000", "0000000000000001", "7fffffffffffffff", "8000000000000000", "ffffffffffffffff"})
    void allU64TimesRoundTrip(String raw) throws Exception {
        byte[] time = hex(raw);
        var key = new CapturingKey();
        byte[] semantic = DeviceWriter.signed(root(), key.identity(), "é\u0000", time, List.of());
        var object = V1EnvelopeWriter.seal(root(), semantic);
        assertEquals(1024, object.bytes().length);
        var read = EnvelopeReader.open(object.id().filename(), object.bytes(), root());
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE, read.status());
        assertArrayEquals(semantic, read.semanticBytes());
        assertTrue(DeviceWriterTest.matches(read.plaintext(), KEY, DeviceWriter.displayName("é\u0000"), time, List.of()));
        var assertion = AssertionValidator.validate(read);
        assertEquals(AssertionValidator.Status.ASSERTION_VALID, assertion.status());
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion.object(), root(), VerificationKeyMaterial.keys()));
        byte[] prk = CryptoSupport.extract(root());
        assertEquals(object.id(), ObjectId.compute(CryptoSupport.idKey(prk), semantic));
        var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, new javax.crypto.spec.SecretKeySpec(
                CryptoSupport.objectKey(CryptoSupport.objectRoot(prk), object.id()), "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, EnvelopeReader.nonce(object.id())));
        cipher.updateAAD(EnvelopeReader.aad(object.id()));
        byte[] padded = cipher.doFinal(object.bytes());
        assertEquals(1008, padded.length);
        assertArrayEquals(CryptoVectorTest.padded(semantic), padded);
        assertEquals(16, object.bytes().length - padded.length);
    }
    @Test void strictNamesAndExactPresentationBytes() throws Exception {
        for (String s : List.of("", "ASCII", "é", "é".repeat(128), "a".repeat(256), "e\u0301", "\u001b[31m")) {
            var key = new CapturingKey();
            var parsed = V1PlaintextParser.parse(DeviceWriter.signed(root(), key.identity(), s, new byte[8], List.of()));
            assertEquals(s, parsed.plaintext().device().displayName());
        }
        assertFalse(Arrays.equals(DeviceWriter.displayName("é"), DeviceWriter.displayName("e\u0301")));
        for (String invalid : List.of("a".repeat(257), "é".repeat(129), "\ud800", "\udc00")) {
            var key = new CapturingKey();
            assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), invalid, new byte[8], List.of()));
            assertEquals(0, key.calls);
        }
        var key = new CapturingKey();
        assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), new byte[]{(byte) 0xff}, new byte[8], List.of()));
        assertEquals(0, key.calls);
    }
    @Test void borrowedNameTimeAndParentCollectionCannotChangePlannedShape() throws Exception {
        var key = new CapturingKey();
        byte[] name = DeviceWriter.displayName("owned"), time = hex("ffffffffffffffff");
        var parents = new ArrayList<>(parents(2));
        var expected = DeviceWriter.canonicalParents(parents);
        key.afterCapture = () -> { Arrays.fill(name, (byte) 0); Arrays.fill(time, (byte) 0); parents.clear(); };
        byte[] semantic = DeviceWriter.signed(root(), key.identity(), name, time, parents);
        assertTrue(DeviceWriterTest.matches(V1PlaintextParser.parse(semantic).plaintext(), KEY,
                DeviceWriter.displayName("owned"), hex("ffffffffffffffff"), expected));
        key.afterCapture = () -> {};
        for (int width : new int[]{0, 7, 9}) {
            assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), "", new byte[width], List.of()));
        }
        assertEquals(1, key.calls);
    }
    @Test void parentsCanonicalAndCapacityReservedBeforeSigning() throws Exception {
        var key = new CapturingKey();
        var input = parents(14);
        byte[] semantic = DeviceWriter.signed(root(), key.identity(), "x".repeat(256), new byte[8], input);
        var sorted = DeviceWriter.canonicalParents(input);
        var parsed = V1PlaintextParser.parse(semantic).plaintext();
        assertEquals(sorted, parsed.routing().parents().stream().map(ObjectId::new).toList());
        byte[] first = key.message.clone();
        DeviceWriter.signed(root(), key.identity(), "x".repeat(256), new byte[8], sorted);
        assertArrayEquals(first, key.message);
        assertTrue(semantic.length <= 973);
        for (int count : new int[]{15, 32, 33}) {
            int before = key.calls;
            assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), "x".repeat(256), new byte[8], parents(count)));
            assertEquals(before, key.calls);
        }
        DeviceWriter.signed(root(), key.identity(), "", new byte[8], parents(22));
        int before = key.calls;
        assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), "", new byte[8], parents(23)));
        assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), key.identity(), "", new byte[8], List.of(input.get(0), input.get(0))));
        assertEquals(before, key.calls);
    }
    @Test void envelopeFixedSignedFixtureDeterministicAndDefensive() throws Exception {
        var v = fixture();
        byte[] semantic = v.semanticBytes();
        var object = V1EnvelopeWriter.seal(root(), semantic);
        assertEquals("6cd79f801c9ab803fcafb9a48aac004a3ca2f7a6999d613ff65ca86bc21968d4", object.id().filename());
        assertArrayEquals(v.data().field("crypto").field("object_hex").hex(), object.bytes());
        assertArrayEquals(object.bytes(), V1EnvelopeWriter.seal(root(), semantic).bytes());
        byte[] saved = object.bytes();
        Arrays.fill(semantic, (byte) 0); Arrays.fill(object.bytes(), (byte) 0);
        assertArrayEquals(saved, object.bytes());
        assertThrows(IllegalArgumentException.class, () -> V1EnvelopeWriter.seal(root(), new byte[1007]));
        assertEquals(1024, V1EnvelopeWriter.seal(root(), new byte[1006]).bytes().length);
        assertEquals("45840a8cd3103186f15cc5134f5e8dfd2957c112769f6d83599a88a1bb0c6750",
                HexFormat.of().formatHex(CryptoSupport.sha256(object.bytes())));
    }

    @Test void localFixedSignedEnvelopeKnownAnswerAndParentedSignatureInput() throws Exception {
        // Implementation-local fixture, captured once with JCA scalar-1 P-256 signing.
        // No signing/randomness is used to reproduce the envelope known answer.
        byte[] semantic = hex("00010001010002000102000400020002000500207900000000000000000000000000000000000000000000000000000000000000000500207a0000000000000000000000000000000000000000000000000000000000000000060008800000000000000002000020f4c5e2661634374eff53ec5a9abc2512f155834804db0fa9207e950d55ee4c3502010041046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f50202000d4d332e31612066697874757265ff01004730450220046e23166adb17940ed7dfe5e91a7dec9702fc8ad57bb1b8127df16a58b4ed4d022100bfd11000b5018c8958498e534eff1e9e0440067da714a6cc8afdebe2a50e99a3");
        var sealed = V1EnvelopeWriter.seal(root(), semantic);
        assertEquals("d68050ec09da8a9544c4d8c1bbae3628f0de73225b75cb04a86731b17638ec47", sealed.id().filename());
        assertEquals("e7122dc0eef2667941d60379519e0989e362aee037e076dd24659e208bf8592b",
                HexFormat.of().formatHex(CryptoSupport.sha256(sealed.bytes())));
        var read = EnvelopeReader.open(sealed.id().filename(), sealed.bytes(), root());
        var assertion = AssertionValidator.validate(read).object();
        assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion, root(), VerificationKeyMaterial.keys()));
        var key = new CapturingKey();
        DeviceWriter.signed(root(), key.identity(), "M3.1a fixture", hex("8000000000000000"), parents(2));
        assertArrayEquals(CryptoSupport.join(hex("746f7469706f2f76312f646576696365551bac2f3e4ad51ec59ad3b7dba4805f51e6a96bdfa736b132cecf15b6d7f156"),
                assertion.unsignedSemantic()), key.message);
    }

    @ParameterizedTest @ValueSource(strings = {
            "30440220439e80b0353fa290dec37f87fd2f98b7b881227dba9b67aa8a4608e5f1d7018b022068a36fa2ef401a268ac880368544e992f43248fec2a9a02f8121b8ce819dd382",
            "3045022100b7d46a60349a00638d71fd5b43bf76ff4aeb6e2e0fb4369d42ee37d0162adcfb022076497249bb02d3150abf4bcf665f75f28017b047eb5220b3560244aaadba3568",
            "3046022100e73af1158ec7efdc905a266e4a24ea16b585cbf527c685fdf66b2989f7f734d3022100834a1f31d50f558b8ac355c9ce696422c0415d820d2456567053777f62db200c"})
    void actual70Through72ByteSignaturesCannotChangeCapacity(String signature) throws Exception {
        // Fixed real JCA signatures of the same 14-parent/max-name message. No retry loop.
        var key = new CapturingKey(); key.fixedSignature = hex(signature);
        var identity = key.identity();
        byte[] semantic = DeviceWriter.signed(root(), identity, "x".repeat(256), new byte[8], parents(14));
        assertEquals(973 - 72 + key.fixedSignature.length, semantic.length);
        assertTrue(P256.verify(KEY, key.message, key.fixedSignature));
        assertThrows(IllegalArgumentException.class, () -> DeviceWriter.signed(root(), identity,
                "x".repeat(256), new byte[8], parents(15)));
        assertEquals(1, key.calls);
    }
    static boolean matches(V1Plaintext value, byte[] key, byte[] display, byte[] time, List<ObjectId> parents) {
        if (value == null || value.device() == null) { return false; }
        var routing = value.routing();
        return routing.version() == 1 && routing.objectType() == 2
                && Arrays.equals(routing.identity(), P256.deviceId(key))
                && Arrays.equals(value.device().publicKey(), key)
                && Arrays.equals(value.device().displayName().getBytes(java.nio.charset.StandardCharsets.UTF_8), display)
                && routing.authorTime().equals(new java.math.BigInteger(1, time))
                && routing.parents().stream().map(ObjectId::new).toList().equals(parents);
    }
}
