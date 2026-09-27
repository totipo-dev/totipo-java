package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class CryptoVectorTest {
    @Test
    void selectsExactlyTheFivePinnedCryptoCases() throws IOException {
        assertEquals(Set.of("v1.crypto.device-root.001", "v1.crypto.future-device-opaque.001",
                "v1.crypto.future-token-opaque.001", "v1.crypto.token-child.001", "v1.crypto.token-root.001"),
                VectorCaseLoader.cryptoCases().stream().map(Case::id).collect(Collectors.toSet()));
    }

    @TestFactory
    List<DynamicTest> allSuppliedDiagnosticsAndRealEnvelopePipelines() throws IOException {
        return VectorCaseLoader.cryptoCases().stream().map(v -> DynamicTest.dynamicTest(
                v.context(), () -> check(v))).toList();
    }

    private static void check(Case vector) throws Exception {
        Node c = vector.data().field("crypto");
        byte[] root = vector.data().field("root_hex").hex();
        byte[] semantic = vector.semanticBytes();
        byte[] prk = CryptoSupport.extract(root);
        byte[] idKey = CryptoSupport.idKey(prk);
        byte[] objectRoot = CryptoSupport.objectRoot(prk);
        assertArrayEquals(c.field("id_key_hex").hex(), idKey);
        assertArrayEquals(c.field("object_root_key_hex").hex(), objectRoot);
        assertArrayEquals(c.field("signature_context_hex").hex(), CryptoSupport.signatureContext(prk));
        ObjectId id = ObjectId.compute(idKey, semantic);
        assertEquals(c.field("object_id").string(), id.filename());
        assertArrayEquals(c.field("object_id").hex(), id.bytes());
        byte[] key = CryptoSupport.objectKey(objectRoot, id);
        assertArrayEquals(c.field("object_key_hex").hex(), key);
        byte[] nonce = EnvelopeReader.nonce(id);
        byte[] aad = EnvelopeReader.aad(id);
        assertArrayEquals(c.field("nonce_hex").hex(), nonce);
        assertArrayEquals(c.field("aad_hex").hex(), aad);
        assertEquals(c.field("semantic_length").integer(), BigInteger.valueOf(semantic.length));
        byte[] padded = padded(semantic);
        assertArrayEquals(c.field("padded_plaintext_hex").hex(), padded);
        byte[] object = c.field("object_hex").hex();
        assertEquals(EnvelopeReader.OBJECT_BYTES, object.length);
        assertArrayEquals(c.field("ciphertext_hex").hex(), Arrays.copyOf(object, EnvelopeReader.PADDED_BYTES));
        assertArrayEquals(c.field("gcm_tag_hex").hex(),
                Arrays.copyOfRange(object, EnvelopeReader.PADDED_BYTES, object.length));
        // Test-only fixed-input encryption independently reproduces ciphertext AND tag.
        assertArrayEquals(object, encrypt(key, nonce, aad, padded));
        assertArrayEquals(padded, crypt(Cipher.DECRYPT_MODE, key, nonce, aad, object));

        var opened = EnvelopeReader.open(id.filename(), object, root);
        switch (vector.expected()) {
            case "SUPPORTED_VALID" -> {
                assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE, opened.status());
                EncodingVectorTest.checkFields(vector.data().field("input"), opened.plaintext());
                var fields = TlvTestBytes.fields(semantic);
                var signature = fields.remove(fields.size() - 1);
                assertEquals(0xff01, signature.tag());
                byte[] unsigned = TlvTestBytes.encode(fields);
                assertArrayEquals(c.field("unsigned_semantic_hex").hex(), unsigned);
                byte[] message = P256.signatureInput(root, opened.routing().prefix().objectType(), unsigned);
                assertArrayEquals(c.field("signature_input_hex").hex(), message);
                assertArrayEquals(c.field("signature_der_hex").hex(), signature.value());
                assertArrayEquals(signature.value(), opened.plaintext().signature());
                byte[] publicKey = c.field("fixture_public_key_hex").hex();
                assertNotNull(P256.decode(publicKey));
                assertTrue(P256.verify(publicKey, message, signature.value()));
                byte[] expectedDevice = opened.plaintext().device() == null
                        ? opened.routing().prefix().authorDeviceId() : opened.routing().prefix().identity();
                assertArrayEquals(expectedDevice, P256.deviceId(publicKey));
                if (opened.plaintext().device() != null) {
                    assertArrayEquals(publicKey, opened.plaintext().device().publicKey());
                }
            }
            case "OPAQUE_ROUTABLE" -> {
                Node future = vector.data().field("future");
                int type = future.field("routing").field("type").integer().intValueExact();
                assertEquals(type == 1 ? EnvelopeReader.Status.AUTHENTICATED_FUTURE_TOKEN
                        : EnvelopeReader.Status.AUTHENTICATED_FUTURE_DEVICE, opened.status());
                assertNull(opened.plaintext());
                RoutingVectorTest.checkFields(future.field("routing"), opened.routing().prefix());
                byte[] tail = future.field("opaque_tail_hex").hex();
                assertArrayEquals(tail, Arrays.copyOfRange(semantic, opened.routing().prefixLength(), semantic.length));
                byte[] prefix = TlvTestBytes.encode(TlvTestBytes.fields(
                        Arrays.copyOf(semantic, opened.routing().prefixLength())));
                assertArrayEquals(semantic, TlvTestBytes.join(prefix, tail));
                // Deliberately not valid v1 TLV framing, yet authenticated and routable.
                assertEquals(TlvReader.Status.TRUNCATED_VALUE, new TlvReader(tail, 0, tail.length).next().status());
            }
            default -> fail("Unexpected crypto expectation: " + vector.expected());
        }
    }

    static Case signedCase() throws IOException {
        return VectorCaseLoader.cryptoCases().stream()
                .filter(v -> v.data().field("operation").string().equals("crypto")).findFirst().orElseThrow();
    }

    static byte[] padded(byte[] semantic) {
        byte[] padded = new byte[EnvelopeReader.PADDED_BYTES];
        padded[0] = (byte) (semantic.length >>> 8);
        padded[1] = (byte) semantic.length;
        System.arraycopy(semantic, 0, padded, 2, semantic.length);
        return padded;
    }

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] aad, byte[] padded) throws Exception {
        return crypt(Cipher.ENCRYPT_MODE, key, nonce, aad, padded);
    }

    private static byte[] crypt(int mode, byte[] key, byte[] nonce, byte[] aad, byte[] input) throws Exception {
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
    }
}
