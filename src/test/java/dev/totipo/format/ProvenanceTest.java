package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.ProvenanceStatus.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.format.AssertionValidator.AssertionValidObject;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.Assumptions;

class ProvenanceTest {
    static Case fixture(String id) throws Exception {
        return VectorCaseLoader.cryptoCases().stream().filter(v -> v.id().equals(id)).findFirst().orElseThrow();
    }
    static Case token() throws Exception { return fixture("v1.crypto.token-root.001"); }
    static Case device() throws Exception { return fixture("v1.crypto.device-root.001"); }
    static byte[] root(Case c) { return c.data().field("root_hex").hex(); }
    static byte[] key(Case c) { return c.data().field("crypto").field("fixture_public_key_hex").hex(); }

    // Test-only deterministic envelope construction; no signing or production writer.
    static EnvelopeReader.Result authenticate(byte[] semantic, byte[] root) throws Exception {
        byte[] prk = CryptoSupport.extract(root);
        ObjectId id = ObjectId.compute(CryptoSupport.idKey(prk), semantic);
        byte[] encrypted = CryptoVectorTest.encrypt(CryptoSupport.objectKey(CryptoSupport.objectRoot(prk), id),
                EnvelopeReader.nonce(id), EnvelopeReader.aad(id), CryptoVectorTest.padded(semantic));
        return EnvelopeReader.open(id.filename(), encrypted, root);
    }
    static AssertionValidObject valid(byte[] bytes, byte[] root) throws Exception {
        var result = AssertionValidator.validate(authenticate(bytes, root));
        assertEquals(AssertionValidator.Status.ASSERTION_VALID, result.status());
        assertNotNull(result.object());
        return result.object();
    }
    static ProvenanceStatus evaluate(AssertionValidObject object, byte[] root, byte[]... keys) {
        return ProvenanceEvaluator.evaluate(object, root, VerificationKeyMaterial.keys(keys));
    }

    @Test
    void exactManifestCoverage() throws Exception {
        assertEquals(Set.of("v1.provenance.token-verified.001", "v1.provenance.token-rejected.001",
                "v1.provenance.token-unresolved.001", "v1.provenance.der-short-valid.001",
                "v1.provenance.der-max-valid.001", "v1.provenance.initial-device-before-token.001",
                "v1.provenance.signature-context-cross-vault.001", "v1.provenance.late-device-reclassify.001"),
                VectorCaseLoader.provenanceCases().stream().map(Case::id).collect(Collectors.toSet()));
    }

    @TestFactory
    List<DynamicTest> portableCases() throws Exception {
        return VectorCaseLoader.provenanceCases().stream().map(c -> DynamicTest.dynamicTest(
                c.id() + " expected=" + c.expected(), () -> {
                    try {
                        switch (c.data().field("operation").string()) {
                            case "provenance" -> {
                                byte[] semantic = TlvTestBytes.replace(token().semanticBytes(), 0xff01,
                                        c.data().field("input").field("signature").base64());
                                var assertion = valid(semantic, root(c));
                                EncodingVectorTest.checkFields(c.data().field("input"), assertion.plaintext());
                                var actual = c.data().has("public_key_hex")
                                        ? evaluate(assertion, root(c), c.data().field("public_key_hex").hex())
                                        : evaluate(assertion, root(c));
                                assertEquals(c.expected(), actual.name());
                                if (actual == VERIFIED) {
                                    assertTrue(EcdsaDerSignature.isCanonical(assertion.plaintext().signature()));
                                }
                                System.out.println(c.id() + " expected=ASSERTION_VALID/" + c.expected()
                                        + " actual=ASSERTION_VALID/" + actual + " PASS; DER bytes="
                                        + assertion.plaintext().signature().length);
                            }
                            case "late-provenance" -> late(c);
                            case "signature-context" -> crossVault(c);
                            case "publication" -> {
                                // This case contains only symbolic writer gate events, no reader trial.
                                var events = c.data().field("publication").field("events").array();
                                assertFalse(events.isEmpty());
                                assertTrue(events.stream().allMatch(e -> Set.of("report-success", "advertise",
                                        "publish-token", "restart-workflow").contains(e.field("action").string())));
                                System.out.println(c.id() + " expected=PASS writer durable/report-success gate; "
                                        + "actual=DEFERRED; M1.4 reader expectations in this case: none");
                                Assumptions.assumeTrue(false, "DEFERRED: durable writer publication/report-success");
                            }
                            default -> fail("Unhandled provenance operation");
                        }
                    } catch (AssertionError failure) {
                        System.out.println(c.id() + " expected=" + c.expected() + " actual=" + failure + " FAIL");
                        throw failure;
                    }
                })).toList();
    }

    private static void late(Case c) throws Exception {
        var contract = c.data().field("late_provenance");
        Case fixture = fixture(contract.field("fixture_case").string());
        for (var trial : contract.field("trials").array()) {
            byte[] semantic = fixture.semanticBytes();
            if (trial.field("corrupt_signature").bool()) { semantic[semantic.length - 1] ^= 1; }
            var opened = authenticate(semantic, root(fixture));
            var assertion = AssertionValidator.validate(opened).object();
            assertNotNull(assertion);
            byte[] before = opened.semanticBytes();
            byte[] unsigned = assertion.unsignedSemantic();
            var plaintext = assertion.plaintext();
            byte[] id = ObjectId.compute(CryptoSupport.idKey(CryptoSupport.extract(root(fixture))), before).bytes();
            var actualBefore = evaluate(assertion, root(fixture));
            var actualAfter = evaluate(assertion, root(fixture), key(fixture));
            assertEquals(trial.field("before").string(), actualBefore.name());
            assertEquals(trial.field("after").string(), actualAfter.name());
            assertTrue(trial.field("semantic_unchanged").bool());
            assertArrayEquals(before, opened.semanticBytes());
            assertArrayEquals(unsigned, assertion.unsignedSemantic());
            assertSame(plaintext, assertion.plaintext());
            assertArrayEquals(id, ObjectId.compute(CryptoSupport.idKey(CryptoSupport.extract(root(fixture))),
                    opened.semanticBytes()).bytes());
            assertEquals(AssertionValidator.Status.ASSERTION_VALID, AssertionValidator.validate(opened).status());
            byte[] expectedSignature = plaintext.signature();
            byte[] originalSignature = fixture.data().field("input").field("signature").base64();
            if (trial.field("corrupt_signature").bool()) { originalSignature[originalSignature.length - 1] ^= 1; }
            assertArrayEquals(originalSignature, expectedSignature);
            // Check every value/routing field against the pinned contract, including parents and credential.
            var original = valid(fixture.semanticBytes(), root(fixture));
            EncodingVectorTest.checkFields(fixture.data().field("input"), original.plaintext());
            assertArrayEquals(original.unsignedSemantic(), assertion.unsignedSemantic());
            System.out.println(c.id() + " expected=" + trial.field("before").string() + "->"
                    + trial.field("after").string() + "/unchanged actual=" + actualBefore + "->" + actualAfter
                    + "/unchanged PASS; durable trigger/index and graph calculations DEFERRED");
        }
    }

    private static void crossVault(Case c) throws Exception {
        var contract = c.data().field("signature_context");
        byte[] semantic = TlvTestBytes.replace(token().semanticBytes(), 0xff01,
                c.data().field("input").field("signature").base64());
        var assertion = valid(semantic, root(token()));
        EncodingVectorTest.checkFields(c.data().field("input"), assertion.plaintext());
        assertArrayEquals(contract.field("unsigned_semantic_hex").hex(), assertion.unsignedSemantic());
        byte[] input = P256.signatureInput(root(token()), 1, assertion.unsignedSemantic());
        int contextOffset = CryptoSupport.ascii("totipo/v1/token").length;
        assertArrayEquals(contract.field("context_a_hex").hex(), Arrays.copyOfRange(input, contextOffset, contextOffset + 32));
        byte[] key = c.data().field("public_key_hex").hex();
        var underA = evaluate(assertion, root(token()), key);
        assertEquals(contract.field("under_a").string(), underA.name());
        // Explicit test-only context diagnostic required by the portable contract; never an evaluator input.
        System.arraycopy(contract.field("context_b_hex").hex(), 0, input, contextOffset, 32);
        var underB = P256.verify(key, input, assertion.plaintext().signature()) ? VERIFIED : REJECTED;
        assertEquals(contract.field("under_b").string(), underB.name());
        byte[] otherRoot = root(token()); otherRoot[0] ^= 1;
        assertEquals(REJECTED, evaluate(assertion, otherRoot, key));
        System.out.println(c.id() + " expected=" + contract.field("under_a").string() + "/"
                + contract.field("under_b").string() + " actual=" + underA + "/" + underB + " PASS");
    }

    @TestFactory
    List<DynamicTest> deviceIdentityCases() throws Exception {
        var cases = VectorCaseLoader.deviceCases().stream().filter(c -> Set.of("v1.device.explicit-id.001",
                "v1.device.id-mismatch.001").contains(c.id())).toList();
        assertEquals(2, cases.size());
        return cases.stream().map(c -> DynamicTest.dynamicTest(c.id(), () -> {
                    var crypto = c.data().field("crypto");
                    var opened = EnvelopeReader.open(crypto.field("object_id").string(),
                            crypto.field("object_hex").hex(), root(c));
                    assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE, opened.status());
                    var actual = AssertionValidator.validate(opened);
                    assertEquals(c.expected(), actual.status() == AssertionValidator.Status.ASSERTION_VALID
                            ? "SUPPORTED_VALID" : "INVALID");
                    if (actual.object() != null) { assertEquals(REJECTED, evaluate(actual.object(), root(c))); }
                    else { assertNull(actual.object()); }
                    System.out.println(c.id() + " expected=" + c.expected() + " actual=" + actual.status() + " PASS");
                })).toList();
    }

    @Test
    void deviceProvenanceNeverGatesTokenKeyMaterialAndReaderCanSeeTokenFirst() throws Exception {
        var d = device(); var t = token();
        var device = valid(d.semanticBytes(), root(d));
        var token = valid(t.semanticBytes(), root(t));
        assertEquals(VERIFIED, evaluate(device, root(d)));
        assertEquals(UNRESOLVED, evaluate(token, root(t)));
        byte[] bad = d.semanticBytes(); bad[bad.length - 1] ^= 1;
        var rejectedDevice = valid(bad, root(d));
        assertEquals(REJECTED, evaluate(rejectedDevice, root(d)));
        assertEquals(VERIFIED, evaluate(token, root(t), rejectedDevice.plaintext().device().publicKey()));
        assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(device, root(d),
                VerificationKeyMaterial.temporarilyUnavailable()));
        assertEquals(VERIFIED, evaluate(token, root(t), device.plaintext().device().publicKey()));
        assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(token, root(t),
                VerificationKeyMaterial.temporarilyUnavailable()));
    }

    @Test
    void offCurveKeyIsIntrinsicValidButRejectsBothKindsOfProvenance() throws Exception {
        byte[] offCurve = new byte[65]; offCurve[0] = 4;
        byte[] derived = P256.deviceId(offCurve);
        var d = device(); var t = token();
        byte[] deviceBytes = TlvTestBytes.replace(TlvTestBytes.replace(d.semanticBytes(), 0x0201, offCurve), 0x0200, derived);
        var device = valid(deviceBytes, root(d));
        assertEquals(REJECTED, evaluate(device, root(d)));
        var token = valid(TlvTestBytes.replace(t.semanticBytes(), 0x0102, derived), root(t));
        assertEquals(UNRESOLVED, evaluate(token, root(t)));
        assertEquals(REJECTED, evaluate(token, root(t), offCurve));
        derived[0] ^= 1;
        var invalid = AssertionValidator.validate(authenticate(TlvTestBytes.replace(deviceBytes, 0x0200, derived), root(d)));
        assertEquals(AssertionValidator.Status.ASSERTION_INVALID, invalid.status());
        assertNull(invalid.object());
    }

    @Test
    void zeroMalformedAndCanonicalMathematicallyInvalidSignaturesKeepAssertionValidity() throws Exception {
        for (var fixture : List.of(token(), device())) {
            for (byte[] signature : List.of(new byte[0], hex("3000"), hex("3006020100020100"),
                    hex("300702020001020101"))) {
                var assertion = valid(TlvTestBytes.replace(fixture.semanticBytes(), 0xff01, signature), root(fixture));
                assertEquals(REJECTED, evaluate(assertion, root(fixture), key(fixture)));
                if (signature.length == 0) { assertEquals(REJECTED, evaluate(assertion, root(fixture))); }
            }
        }
        assertTrue(EcdsaDerSignature.isCanonical(hex("3006020100020100")));
    }

    @Test
    void matchingDuplicatesAreHarmless() throws Exception {
        var t = token(); var assertion = valid(t.semanticBytes(), root(t));
        byte[] key = key(t);
        byte[] unrelated = new byte[65]; unrelated[0] = 4;
        assertEquals(UNRESOLVED, evaluate(assertion, root(t), unrelated));
        assertEquals(VERIFIED, evaluate(assertion, root(t), key, key));
    }

    @Test
    void falseClaimDoesNotCreateMatchingKey() throws Exception {
        var t = token(); var assertion = valid(t.semanticBytes(), root(t));
        byte[] unrelated = otherValidKey(t);
        byte[] author = assertion.plaintext().routing().authorDeviceId();
        assertFalse(Arrays.equals(author, P256.deviceId(unrelated)));
        assertNotNull(P256.decode(unrelated));
        var wrongClaim = new VerificationKeyMaterial.Candidate(author, unrelated);
        assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(assertion, root(t),
                VerificationKeyMaterial.available(List.of(wrongClaim))));
    }

    @Test
    void twoFalseClaimsDoNotCreateCollisionRejection() throws Exception {
        var t = token(); var assertion = valid(t.semanticBytes(), root(t));
        byte[] author = assertion.plaintext().routing().authorDeviceId();
        byte[] first = otherValidKey(t);
        byte[] second = new byte[65]; second[0] = 4;
        assertFalse(Arrays.equals(first, second));
        assertFalse(Arrays.equals(author, P256.deviceId(first)));
        assertFalse(Arrays.equals(author, P256.deviceId(second)));
        assertFalse(Arrays.equals(P256.deviceId(first), P256.deviceId(second)));
        var a = new VerificationKeyMaterial.Candidate(author, first);
        var b = new VerificationKeyMaterial.Candidate(author, second);
        for (var candidates : List.of(List.of(a, b), List.of(b, a))) {
            assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(assertion, root(t),
                    VerificationKeyMaterial.available(candidates)));
        }
    }

    @Test
    void falseClaimDoesNotPoisonRealMatchingKey() throws Exception {
        var t = token(); var assertion = valid(t.semanticBytes(), root(t));
        byte[] author = assertion.plaintext().routing().authorDeviceId();
        byte[] unrelated = otherValidKey(t);
        assertArrayEquals(author, P256.deviceId(key(t)));
        assertFalse(Arrays.equals(author, P256.deviceId(unrelated)));
        var wrongClaim = new VerificationKeyMaterial.Candidate(author, unrelated);
        var good = new VerificationKeyMaterial.Candidate(author, key(t));
        byte[] corrupt = t.semanticBytes(); corrupt[corrupt.length - 1] ^= 1;
        var invalidSignature = valid(corrupt, root(t));
        for (var candidates : List.of(List.of(good, wrongClaim), List.of(wrongClaim, good))) {
            assertEquals(VERIFIED, ProvenanceEvaluator.evaluate(assertion, root(t),
                    VerificationKeyMaterial.available(candidates)));
            assertEquals(REJECTED, ProvenanceEvaluator.evaluate(invalidSignature, root(t),
                    VerificationKeyMaterial.available(candidates)));
        }
    }

    @Test
    void nonmatchingClaimCannotForceRejected() throws Exception {
        var t = token(); var assertion = valid(t.semanticBytes(), root(t));
        byte[] offCurve = new byte[65]; offCurve[0] = 4;
        byte[] author = assertion.plaintext().routing().authorDeviceId();
        assertFalse(Arrays.equals(author, P256.deviceId(offCurve)));
        assertThrows(IllegalArgumentException.class, () -> P256.decode(offCurve));
        var wrongClaim = new VerificationKeyMaterial.Candidate(author, offCurve);
        assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(assertion, root(t),
                VerificationKeyMaterial.available(List.of(wrongClaim))));
    }

    @Test
    void actualMatchingInvalidKeyStillRejects() throws Exception {
        var t = token();
        // Same deterministic off-curve bytes as the existing DEVICE separation test.
        byte[] offCurve = new byte[65]; offCurve[0] = 4;
        byte[] derived = P256.deviceId(offCurve);
        var assertion = valid(TlvTestBytes.replace(t.semanticBytes(), 0x0102, derived), root(t));
        assertArrayEquals(derived, assertion.plaintext().routing().authorDeviceId());
        assertThrows(IllegalArgumentException.class, () -> P256.decode(offCurve));
        assertEquals(UNRESOLVED, evaluate(assertion, root(t)));
        assertEquals(REJECTED, evaluate(assertion, root(t), offCurve));
    }

    private static byte[] otherValidKey(Case fixture) {
        // Negate the fixed point: deterministic valid P-256 material, no signing/key generation.
        byte[] key = key(fixture);
        var decoded = P256.decode(key);
        var p = ((java.security.spec.ECFieldFp) decoded.getParams().getCurve().getField()).getP();
        byte[] y = p.subtract(decoded.getW().getAffineY()).toByteArray();
        Arrays.fill(key, 33, 65, (byte) 0);
        int length = Math.min(32, y.length);
        System.arraycopy(y, y.length - length, key, 65 - length, length);
        return key;
    }

    @Test
    void ownedInputsAndOutputsCannotChangeEvaluation() throws Exception {
        var t = token(); byte[] semantic = t.semanticBytes();
        var opened = authenticate(semantic, root(t));
        var assertion = AssertionValidator.validate(opened).object();
        byte[] key = key(t); byte[] author = assertion.plaintext().routing().authorDeviceId();
        var candidate = new VerificationKeyMaterial.Candidate(author, key);
        var material = VerificationKeyMaterial.available(List.of(candidate));
        Arrays.fill(key, (byte) 0); Arrays.fill(author, (byte) 0); Arrays.fill(semantic, (byte) 0);
        Arrays.fill(candidate.publicKey(), (byte) 0); Arrays.fill(candidate.claimedDeviceId(), (byte) 0);
        Arrays.fill(opened.semanticBytes(), (byte) 0); Arrays.fill(assertion.unsignedSemantic(), (byte) 0);
        Arrays.fill(assertion.plaintext().signature(), (byte) 0);
        Arrays.fill(assertion.plaintext().routing().identity(), (byte) 0);
        Arrays.fill(assertion.plaintext().routing().authorDeviceId(), (byte) 0);
        Arrays.fill(assertion.plaintext().token().credential().secret(), (byte) 0);
        assertEquals(VERIFIED, ProvenanceEvaluator.evaluate(assertion, root(t), material));
        EncodingVectorTest.checkFields(t.data().field("input"), assertion.plaintext());
    }

    @Test
    void futureObjectsNeverReceiveV1AssertionOrProvenanceClassification() throws Exception {
        for (String name : List.of("v1.crypto.future-token-opaque.001", "v1.crypto.future-device-opaque.001")) {
            var c = fixture(name); var crypto = c.data().field("crypto");
            var opened = EnvelopeReader.open(crypto.field("object_id").string(), crypto.field("object_hex").hex(), root(c));
            assertNull(opened.plaintext()); assertNull(opened.semanticBytes());
            assertThrows(IllegalArgumentException.class, () -> AssertionValidator.validate(opened));
        }
    }

    @Test
    void bothHighAndLowSAcceptedWithoutSigningOrNormalization() throws Exception {
        var t = token(); var original = valid(t.semanticBytes(), root(t));
        byte[] sig = original.plaintext().signature();
        int rLength = sig[3] & 0xff;
        int sStart = 6 + rLength;
        var s = new BigInteger(1, Arrays.copyOfRange(sig, sStart, sig.length));
        var order = P256.decode(key(t)).getParams().getOrder();
        byte[] otherS = order.subtract(s).toByteArray();
        byte[] other = new byte[6 + rLength + otherS.length];
        System.arraycopy(sig, 0, other, 0, 4 + rLength);
        other[1] = (byte) (other.length - 2); other[4 + rLength] = 2;
        other[5 + rLength] = (byte) otherS.length;
        System.arraycopy(otherS, 0, other, sStart, otherS.length);
        assertTrue(s.compareTo(order.shiftRight(1)) * order.subtract(s).compareTo(order.shiftRight(1)) < 0);
        assertTrue(EcdsaDerSignature.isCanonical(sig)); assertTrue(EcdsaDerSignature.isCanonical(other));
        assertEquals(VERIFIED, evaluate(original, root(t), key(t)));
        var transformed = valid(TlvTestBytes.replace(t.semanticBytes(), 0xff01, other), root(t));
        assertEquals(VERIFIED, evaluate(transformed, root(t), key(t)));
        assertArrayEquals(sig, original.plaintext().signature());
    }

    static byte[] hex(String value) { return HexFormat.of().parseHex(value); }
}
