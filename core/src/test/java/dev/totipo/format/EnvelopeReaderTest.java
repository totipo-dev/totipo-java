package dev.totipo.format;

import static dev.totipo.format.CryptoVectorTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class EnvelopeReaderTest {
    @Test
    void everyPhysicalTruncationAndOversizeFailsBeforeCrypto() throws Exception {
        var v = signedCase();
        var c = v.data().field("crypto");
        byte[] object = c.field("object_hex").hex();
        String filename = c.field("object_id").string();
        byte[] root = v.data().field("root_hex").hex();
        // Includes both sides of ciphertext/tag boundary (1008), empty and 1023.
        for (int length = 0; length < object.length; length++) {
            assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE,
                    EnvelopeReader.open(filename, Arrays.copyOf(object, length), root));
        }
        assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE,
                EnvelopeReader.open(filename, Arrays.copyOf(object, object.length + 1), root));
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE,
                EnvelopeReader.open(filename, object, root).status());
        for (String bad : List.of("", filename.toUpperCase(java.util.Locale.ROOT), filename.substring(1),
                filename + "0", "../" + filename, "g" + filename.substring(1), " " + filename.substring(1))) {
            assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE, EnvelopeReader.open(bad, object, root));
        }
    }

    @Test
    void mutationsOfEveryCiphertextAndTagByteNeverPublishPlaintext() throws Exception {
        // Includes both future cases: failed authentication cannot become opacity.
        for (var v : VectorCaseLoader.cryptoCases()) {
            var c = v.data().field("crypto");
            byte[] object = c.field("object_hex").hex();
            byte[] root = v.data().field("root_hex").hex();
            String filename = c.field("object_id").string();
            for (int i = 0; i < object.length; i++) {
                object[i] ^= 1;
                assertFailure(EnvelopeReader.Status.AUTHENTICATION_FAILED, EnvelopeReader.open(filename, object, root));
                object[i] ^= 1;
            }
            root[0] ^= 1;
            assertFailure(EnvelopeReader.Status.AUTHENTICATION_FAILED, EnvelopeReader.open(filename, object, root));
        }
    }

    @Test
    void fullIdKeyDerivationNonceAndAadAreAllAuthenticated() throws Exception {
        var v = signedCase();
        var c = v.data().field("crypto");
        byte[] root = v.data().field("root_hex").hex();
        byte[] object = c.field("object_hex").hex();
        byte[] key = c.field("object_key_hex").hex();
        byte[] nonce = c.field("nonce_hex").hex();
        byte[] aad = c.field("aad_hex").hex();
        String filename = c.field("object_id").string();
        for (int i : new int[]{0, 11, 12, 31}) {
            byte[] id = c.field("object_id").hex();
            id[i] ^= 1;
            assertFailure(EnvelopeReader.Status.AUTHENTICATION_FAILED,
                    EnvelopeReader.open(new ObjectId(id).filename(), object, root));
        }
        // Nonce and AAD are derived, not stored. Encrypt with each wrong parameter
        // independently to isolate the reader's use of those exact fields.
        for (byte[] parameter : new byte[][]{key, nonce, aad}) {
            parameter[0] ^= 1;
            byte[] changed = encrypt(key, nonce, aad, c.field("padded_plaintext_hex").hex());
            assertFailure(EnvelopeReader.Status.AUTHENTICATION_FAILED, EnvelopeReader.open(filename, changed, root));
            parameter[0] ^= 1;
        }
    }

    @Test
    void validTagDoesNotBypassLengthPaddingOrKeyedIdentity() throws Exception {
        var v = signedCase();
        var c = v.data().field("crypto");
        byte[] root = v.data().field("root_hex").hex();
        String filename = c.field("object_id").string();
        byte[] key = c.field("object_key_hex").hex();
        byte[] nonce = c.field("nonce_hex").hex();
        byte[] aad = c.field("aad_hex").hex();
        for (int length : new int[]{1007, 1008, 65535}) {
            byte[] padded = c.field("padded_plaintext_hex").hex();
            padded[0] = (byte) (length >>> 8);
            padded[1] = (byte) length;
            assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE,
                    EnvelopeReader.open(filename, encrypt(key, nonce, aad, padded), root));
        }
        for (int offset : new int[]{2 + v.semanticBytes().length, EnvelopeReader.PADDED_BYTES - 1}) {
            byte[] padded = c.field("padded_plaintext_hex").hex();
            padded[offset] = 1;
            assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE,
                    EnvelopeReader.open(filename, encrypt(key, nonce, aad, padded), root));
        }
        byte[] padded = c.field("padded_plaintext_hex").hex();
        padded[2] ^= 1; // Semantic byte covered by OBJECT_ID. Re-authenticate under old ID.
        assertFailure(EnvelopeReader.Status.OBJECT_ID_MISMATCH,
                EnvelopeReader.open(filename, encrypt(key, nonce, aad, padded), root));
    }

    @Test
    void authenticatedSemanticFailuresAreSeparateFromEnvelopeFailures() throws Exception {
        var v = signedCase();
        byte[] root = v.data().field("root_hex").hex();
        byte[] brokenBody = v.semanticBytes();
        brokenBody[brokenBody.length - v.data().field("crypto").field("signature_der_hex").hex().length - 4] = 0;
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_INVALID_STRUCTURE, consume(root, brokenBody).status());
        byte[] brokenPrefix = v.semanticBytes();
        brokenPrefix[0] = 1;
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_INVALID_STRUCTURE, consume(root, brokenPrefix).status());
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_INVALID_STRUCTURE, consume(root, new byte[0]).status());
        for (int length : new int[]{10, 1006}) {
            byte[] unknown = Arrays.copyOf(v.semanticBytes(), length);
            unknown[9] = 99;
            assertEquals(EnvelopeReader.Status.AUTHENTICATED_OPAQUE_UNSCOPED, consume(root, unknown).status());
        }
        byte[] badFuture = v.semanticBytes();
        badFuture[4] = 2;
        badFuture[10] = 1;
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_OPAQUE_UNSCOPED, consume(root, badFuture).status());
    }

    private static EnvelopeReader.Result consume(byte[] root, byte[] semantic) throws Exception {
        byte[] prk = CryptoSupport.extract(root);
        var id = ObjectId.compute(CryptoSupport.idKey(prk), semantic);
        byte[] key = CryptoSupport.objectKey(CryptoSupport.objectRoot(prk), id);
        return EnvelopeReader.open(id.filename(), encrypt(key, EnvelopeReader.nonce(id),
                EnvelopeReader.aad(id), padded(semantic)), root);
    }

    private static void assertFailure(EnvelopeReader.Status status, EnvelopeReader.Result result) {
        assertEquals(status, result.status());
        assertNull(result.routing());
        assertNull(result.plaintext());
    }
}
