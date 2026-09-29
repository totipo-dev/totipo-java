package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Case;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class BootstrapVectorTest {
    @Test
    void pinsBootstrapCategory() throws Exception {
        assertEquals(Set.of("v1.bootstrap.ascii.001", "v1.bootstrap.empty.001", "v1.bootstrap.unicode.001", "v1.bootstrap.rewrap.001"),
                VectorCaseLoader.bootstrapCases().stream().map(Case::id).collect(Collectors.toSet()));
    }

    @TestFactory
    List<DynamicTest> allDiagnosticsAndProductionUnlock() throws Exception {
        return VectorCaseLoader.bootstrapCases().stream().filter(v -> v.data().field("operation").string().equals("bootstrap")).map(v -> DynamicTest.dynamicTest(
                v.context(), () -> check(v))).toList();
    }

    static void check(Case vector) throws Exception {
        assertEquals("VALID", vector.expected());
        var b = vector.data().field("bootstrap");
        byte[] password = b.field("password_hex").hex();
        byte[] original = password.clone();
        byte[] record = b.field("record_hex").hex();
        var parsed = VaultBootstrap.parse(record);
        assertNotNull(parsed);
        assertEquals(87, record.length);
        assertArrayEquals(b.field("salt_hex").hex(), parsed.salt());
        assertArrayEquals(b.field("nonce_hex").hex(), parsed.nonce());
        assertArrayEquals(b.field("header_hex").hex(), parsed.header());
        assertArrayEquals(CryptoSupport.join(CryptoSupport.ascii("TOTIPO-VLT"), new byte[]{1},
                b.field("salt_hex").hex(), b.field("nonce_hex").hex()), parsed.header());

        var calls = new AtomicInteger();
        var production = new BouncyCastleArgon2idKdf();
        var unlocker = new VaultUnlocker((bytes, salt) -> {
            calls.incrementAndGet();
            assertSame(password, bytes); // Exact caller bytes, without conversion or copying.
            byte[] key = production.derive(bytes, salt);
            assertTrue(Arrays.equals(b.field("wrap_key_hex").hex(), key), "Wrapping key known answer");
            return key;
        });
        var result = unlocker.unlock(record, password);
        assertEquals(1, calls.get());
        assertEquals(VaultUnlockResult.Status.UNLOCKED, result.status());
        assertTrue(Arrays.equals(vector.data().field("root_hex").hex(), result.root()), "Root known answer");
        assertTrue(Arrays.equals(b.field("fingerprint_hex").hex(), result.fingerprint()), "Fingerprint known answer");
        assertArrayEquals(original, password);

        // Decode only public fixture input to obtain characters; production never converts password bytes to String.
        var decoder = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        var decoded = decoder.decode(ByteBuffer.wrap(original));
        char[] characters = new char[decoded.remaining()];
        decoded.get(characters);
        assertArrayEquals(original, PasswordBytes.encode(characters));
        var characterResult = new VaultUnlocker().unlock(record, characters);
        assertEquals(VaultUnlockResult.Status.UNLOCKED, characterResult.status());
        assertTrue(Arrays.equals(result.root(), characterResult.root()), "Character-input root known answer");

        // Fixed public fixture encryption is test-only; independently reproduces both ciphertext and tag.
        byte[] encrypted = EnvelopeTestBytes.encrypt(b.field("wrap_key_hex").hex(), b.field("nonce_hex").hex(),
                b.field("header_hex").hex(), vector.data().field("root_hex").hex());
        assertArrayEquals(Arrays.copyOfRange(record, 39, 71), Arrays.copyOf(encrypted, 32));
        assertArrayEquals(Arrays.copyOfRange(record, 71, 87), Arrays.copyOfRange(encrypted, 32, 48));
        assertArrayEquals(record, CryptoSupport.join(parsed.header(), encrypted));

        // Assert the root relationship from fixture data before opening the opaque envelope.
        var object = EnvelopeTestBytes.fixture();
        assertTrue(Arrays.equals(vector.data().field("root_hex").hex(), object.data().field("root_hex").hex()),
                "Bootstrap and object fixtures share a root");
        var crypto = object.data().field("crypto");
        var opened = EnvelopeReader.open(crypto.field("object_id").string(), crypto.field("object_hex").hex(), result.root());
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_SEMANTIC, opened.status());
        assertArrayEquals(object.semanticBytes(), opened.semanticBytes());
    }

    @Test
    void realCostWrongPasswordAndAuthenticatedMutationsExposeNoRoot() throws Exception {
        var b = VectorCaseLoader.bootstrapCases().get(0).data().field("bootstrap");
        var unlocker = new VaultUnlocker();
        checkFailure(unlocker.unlock(b.field("record_hex").hex(), new byte[]{'w', 'r', 'o', 'n', 'g'}));
        // Salt and nonce are the only structurally mutable header fields.
        for (int offset : new int[]{11, 27, 39, 71}) {
            byte[] record = b.field("record_hex").hex();
            record[offset] ^= 1;
            assertNotNull(VaultBootstrap.parse(record));
            checkFailure(unlocker.unlock(record, b.field("password_hex").hex()));
        }
    }

    private static void checkFailure(VaultUnlockResult result) {
        assertEquals(VaultUnlockResult.Status.AUTHENTICATION_FAILED, result.status());
        assertNull(result.root());
        assertThrows(IllegalStateException.class, result::fingerprint);
    }
}
