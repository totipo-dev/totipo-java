package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import org.totipo.conformance.VectorCaseLoader.Case;
import org.totipo.conformance.VectorCaseLoader.Node;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Optional;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Corpus oracle for the semantic/envelope boundary; no upstream implementation. */
final class TokenVectorChecks {
    private TokenVectorChecks() {}

    static void check(Case vector) throws Exception {
        var data = vector.data();
        if (data.has("post_aead")) {
            postAead(vector);
            return;
        }
        var crypto = data.field("crypto");
        byte[] root = data.field("root_hex").hex();
        byte[] semantic = vector.semanticBytes();
        byte[] object = crypto.field("object_hex").hex();
        var id = ObjectId.fromFilename(crypto.field("object_id").string());
        // This also proves authenticated INVALID grammar is not an AEAD failure.
        var opened = EnvelopeReader.open(id.filename(), object, root);
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_SEMANTIC, opened.status());
        assertEquals(id, opened.objectId());
        assertArrayEquals(semantic, opened.semanticBytes());
        assertEquals(semantic.length, crypto.field("semantic_length").integer().intValueExact());
        assertEquals(1024, object.length);
        intermediates(root, semantic, id, crypto);

        switch (vector.expected()) {
            case "INVALID" -> assertThrows(IllegalArgumentException.class, () -> TokenReader.read(opened.semanticBytes()));
            case "SUPPORTED_VALID" -> {
                var token = TokenReader.read(opened.semanticBytes());
                compareInput(token, data.field("input"));
                byte[] encoded = TokenWriter.write(token);
                assertArrayEquals(semantic, encoded);
                var sealed = V1EnvelopeWriter.seal(root, encoded);
                assertEquals(id, sealed.id());
                assertArrayEquals(object, sealed.bytes());
                if (vector.path().startsWith("cases/size/")) {
                    assertEquals(1005, semantic.length);
                    assertEquals(TokenObject.MAX_PARENTS, token.parents().size());
                }
            }
            default -> fail("Unhandled expected result " + vector.expected());
        }
    }

    private static void compareInput(TokenObject token, Node input) {
        assertArrayEquals(input.field("identity").base64(), token.tokenId().bytes());
        var parents = input.field("parents").array();
        assertEquals(parents.size(), token.parents().size());
        for (int i = 0; i < parents.size(); i++) {
            assertArrayEquals(parents.get(i).base64(), token.parents().get(i).bytes());
        }
        var value = token.value();
        var credential = value.credential();
        assertEquals(input.field("status").integer().intValueExact(), value.status());
        assertEquals(input.field("issuer").string(), value.issuer());
        assertEquals(input.field("account").string(), value.account());
        assertEquals(input.field("algorithm").integer().intValueExact(), credential.algorithm());
        assertEquals(input.field("digits").integer().intValueExact(), credential.digits());
        assertEquals(input.field("period").integer().longValueExact(), credential.period());
        assertArrayEquals(input.field("secret").base64(), credential.secret().bytes());
        assertEquals(input.has("client_name") ? Optional.of(input.field("client_name").string()) : Optional.empty(),
                token.metadata().clientName());
        assertEquals(input.has("client_time") ? Optional.of(input.field("client_time").integer().toString()) : Optional.empty(),
                token.metadata().clientTime().map(UInt64::toString));
    }

    private static void intermediates(byte[] root, byte[] semantic, ObjectId id, Node crypto) throws Exception {
        byte[] prk = CryptoSupport.extract(root);
        byte[] idKey = CryptoSupport.idKey(prk);
        byte[] objectRoot = CryptoSupport.objectRoot(prk);
        byte[] key = CryptoSupport.objectKey(objectRoot, id);
        assertArrayEquals(crypto.field("id_key_hex").hex(), idKey);
        assertArrayEquals(crypto.field("object_root_key_hex").hex(), objectRoot);
        assertArrayEquals(crypto.field("object_key_hex").hex(), key);
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(idKey, "HmacSHA256"));
        assertArrayEquals(id.bytes(), hmac.doFinal(semantic));
        byte[] nonce = crypto.field("nonce_hex").hex();
        byte[] aad = crypto.field("aad_hex").hex();
        assertArrayEquals(nonce, EnvelopeReader.nonce(id));
        assertArrayEquals(aad, EnvelopeReader.aad(id));
        byte[] padded = ByteBuffer.allocate(1008).putShort((short) semantic.length).put(semantic).array();
        assertArrayEquals(crypto.field("padded_plaintext_hex").hex(), padded);
        byte[] encrypted = EnvelopeTestBytes.encrypt(key, nonce, aad, padded);
        assertArrayEquals(crypto.field("ciphertext_hex").hex(), Arrays.copyOf(encrypted, 1008));
        assertArrayEquals(crypto.field("gcm_tag_hex").hex(), Arrays.copyOfRange(encrypted, 1008, 1024));
        assertArrayEquals(crypto.field("object_hex").hex(), encrypted);
    }

    private static void postAead(Case vector) throws Exception {
        assertEquals("INVALID_STORAGE", vector.expected());
        var data = vector.data();
        var fixture = data.field("post_aead");
        byte[] root = data.field("root_hex").hex();
        var id = ObjectId.fromFilename(fixture.field("object_id").string());
        byte[] object = fixture.field("object_hex").hex();
        assertEquals(1024, object.length);
        byte[] prk = CryptoSupport.extract(root);
        byte[] key = CryptoSupport.objectKey(CryptoSupport.objectRoot(prk), id);
        var cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, EnvelopeReader.nonce(id)));
        cipher.updateAAD(EnvelopeReader.aad(id));
        byte[] plaintext = cipher.doFinal(object); // Raw authentication MUST succeed.
        assertArrayEquals(fixture.field("encryption_plaintext_hex").hex(), plaintext);
        assertEquals(1008, plaintext.length);
        int length = Short.toUnsignedInt(ByteBuffer.wrap(plaintext).getShort());
        byte[] semantic = vector.semanticBytes();
        assertArrayEquals(semantic, Arrays.copyOfRange(plaintext, 2, 2 + semantic.length));
        boolean matchingId = id.equals(ObjectId.compute(CryptoSupport.idKey(prk), semantic));
        boolean zeroPadding = true;
        for (int i = 2 + semantic.length; i < plaintext.length; i++) zeroPadding &= plaintext[i] == 0;
        EnvelopeReader.Status expected;
        switch (fixture.field("defect").string()) {
            case "nonzero-padding" -> {
                assertEquals(semantic.length, length);
                assertTrue(matchingId);
                assertFalse(zeroPadding);
                expected = EnvelopeReader.Status.INVALID_ENVELOPE;
            }
            case "object-id-mismatch" -> {
                assertEquals(semantic.length, length);
                assertFalse(matchingId);
                assertTrue(zeroPadding);
                expected = EnvelopeReader.Status.OBJECT_ID_MISMATCH;
            }
            case "semantic-length-invalid" -> {
                assertTrue(length > EnvelopeReader.SEMANTIC_CAPACITY);
                assertTrue(matchingId);
                assertTrue(zeroPadding);
                expected = EnvelopeReader.Status.INVALID_ENVELOPE;
            }
            default -> throw new AssertionError("Unhandled post-AEAD defect");
        }
        var result = EnvelopeReader.open(id.filename(), object, root);
        assertEquals(expected, result.status());
        assertNull(result.objectId());
        assertNull(result.semanticBytes());
        // Compose only on success; the parser is never invoked on a failed envelope.
        TokenObject token = result.status() == EnvelopeReader.Status.AUTHENTICATED_SEMANTIC
                ? TokenReader.read(result.semanticBytes()) : null;
        assertNull(token);
    }
}
