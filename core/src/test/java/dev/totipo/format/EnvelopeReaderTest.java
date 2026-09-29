package dev.totipo.format;

import static dev.totipo.format.EnvelopeTestBytes.*;
import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class EnvelopeReaderTest {
    @Test
    void everyPhysicalTruncationAndOversizeFailsBeforeCrypto() throws Exception {
        var v = fixture();
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
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_SEMANTIC,
                EnvelopeReader.open(filename, object, root).status());
        for (String bad : List.of("", filename.toUpperCase(java.util.Locale.ROOT), filename.substring(1),
                filename + "0", "../" + filename, "g" + filename.substring(1), " " + filename.substring(1))) {
            assertFailure(EnvelopeReader.Status.INVALID_ENVELOPE, EnvelopeReader.open(bad, object, root));
        }
    }

    @Test
    void mutationsOfEveryCiphertextAndTagByteNeverPublishPlaintext() throws Exception {
        // Authentication failure never exposes semantic bytes.
        for (var v : List.of(fixture())) {
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
        var v = fixture();
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
        var v = fixture();
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
    void arbitrarySemanticBytesAreReturnedWithoutGrammarParsingAndOwnTheirStorage() {
        byte[] root = new byte[32];
        for (int length : new int[]{0, 1, 10, 1006}) {
            byte[] semantic = new byte[length];
            Arrays.fill(semantic, (byte) 0xff);
            var sealed = V1EnvelopeWriter.seal(root, semantic);
            byte[] physical = sealed.bytes();
            var opened = EnvelopeReader.open(sealed.id().filename(), physical, root);
            assertEquals(EnvelopeReader.Status.AUTHENTICATED_SEMANTIC, opened.status());
            assertEquals(sealed.id(), opened.objectId());
            assertArrayEquals(semantic, opened.semanticBytes());
            Arrays.fill(physical, (byte) 0);
            Arrays.fill(opened.semanticBytes(), (byte) 0);
            assertArrayEquals(semantic, opened.semanticBytes());
        }
        assertThrows(IllegalArgumentException.class, () -> V1EnvelopeWriter.seal(root, new byte[1007]));
    }

    private static void assertFailure(EnvelopeReader.Status status, EnvelopeReader.Result result) {
        assertEquals(status, result.status());
        assertNull(result.objectId());
        assertNull(result.semanticBytes());
    }
}
