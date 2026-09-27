package dev.totipo.format;

import static dev.totipo.format.TlvTestBytes.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class V1PlaintextParserTest {
    private static byte[] token;
    private static byte[] device;

    @BeforeAll
    static void loadCanonicalSamples() throws Exception {
        for (var vector : VectorCaseLoader.encodingCases()) {
            switch (vector.id()) {
                case "v1.encoding.token-root.001" -> token = vector.semanticBytes();
                case "v1.encoding.device-root.001" -> device = vector.semanticBytes();
                default -> { }
            }
        }
        assertNotNull(token);
        assertNotNull(device);
    }

    @Test
    void everyRequiredFieldIsSingleAndInExactOrder() {
        for (byte[] sample : List.of(token, device)) {
            var original = fields(sample);
            valid(sample);
            for (int i = 0; i < original.size(); i++) {
                var missing = new ArrayList<>(original);
                missing.remove(i);
                invalid(encode(missing));
                var duplicate = new ArrayList<>(original);
                duplicate.add(i, original.get(i));
                invalid(encode(duplicate));
                if (i + 1 < original.size()) {
                    var reversed = new ArrayList<>(original);
                    Collections.swap(reversed, i, i + 1);
                    invalid(encode(reversed));
                }
            }
        }
    }

    @Test
    void nestedCredentialRequiresItsOwnExactCanonicalSequence() {
        var original = fields(credential(token));
        for (int i = 0; i < original.size(); i++) {
            var missing = new ArrayList<>(original);
            missing.remove(i);
            invalid(replace(token, 0x0106, encode(missing)));
            var duplicate = new ArrayList<>(original);
            duplicate.add(i, original.get(i));
            invalid(replace(token, 0x0106, encode(duplicate)));
            if (i + 1 < original.size()) {
                var reversed = new ArrayList<>(original);
                Collections.swap(reversed, i, i + 1);
                invalid(replace(token, 0x0106, encode(reversed)));
            }
        }
        for (int end = 0; end < credential(token).length; end++) {
            invalid(replace(token, 0x0106, Arrays.copyOf(credential(token), end)));
        }
        invalid(replace(token, 0x0106, join(credential(token), field(0x0305))));
        invalid(replace(token, 0x0106, join(credential(token), new byte[]{0})));
    }

    @Test
    void parentCountAndUnsignedOrderAreEnforcedByReusedRouting() {
        byte[][] parents = new byte[4][32];
        for (int i = 0; i < 4; i++) {
            parents[i][31] = (byte) new int[]{0, 0x7f, 0x80, 0xff}[i];
        }
        for (byte[] sample : List.of(token, device)) {
            byte[] ordered = parents(sample, parents);
            assertEquals(4, valid(ordered).routing().parents().size());
            var encoded = fields(ordered);
            Collections.swap(encoded, 4, 5);
            invalid(encode(encoded));
            invalid(parents(sample, parents[0], parents[1], parents[1]));
            invalid(replace(ordered, 4, new byte[]{0, 3}));
            invalid(replace(ordered, 4, new byte[]{0, 5}));
            invalid(replace(ordered, 4, new byte[]{0, 33}));
            invalid(replace(ordered, 4, new byte[]{(byte) 0xff, (byte) 0xff}));
            var interrupted = fields(ordered);
            Collections.swap(interrupted, 6, 7); // AUTHOR_TIME interrupts parent repetition.
            invalid(encode(interrupted));
        }
    }

    @Test
    void unsignedTimeCoversTheEntireDomainWithoutDateOrSignedLongCoercion() {
        String[] binary = {"0000000000000000", "0000000000000001", "7fffffffffffffff",
                "8000000000000000", "ffffffffffffffff", "0102030405060708"};
        BigInteger[] expected = {BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(Long.MAX_VALUE),
                BigInteger.ONE.shiftLeft(63), BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE),
                new BigInteger("72623859790382856")};
        for (int i = 0; i < binary.length; i++) {
            byte[] time = HexFormat.of().parseHex(binary[i]);
            assertEquals(expected[i], valid(replace(token, 6, time)).routing().authorTime());
            assertEquals(expected[i], valid(replace(device, 6, time)).routing().authorTime());
        }
    }

    @Test
    void credentialEnumsAndUnsignedPeriodUseOnlyDefinedV1Values() {
        for (int algorithm : new int[]{1, 2, 3}) {
            for (int digits : new int[]{6, 7, 8}) {
                byte[] credential = replace(credential(token), 0x0301, new byte[]{(byte) algorithm});
                credential = replace(credential, 0x0302, new byte[]{(byte) digits});
                valid(replace(token, 0x0106, credential));
            }
        }
        for (String hex : List.of("00000001", "7fffffff", "80000000", "ffffffff", "01020304")) {
            byte[] changed = replaceCredential(0x0303, HexFormat.of().parseHex(hex));
            assertEquals(Long.parseLong(hex, 16), valid(changed).token().credential().period());
        }
        invalid(replaceCredential(0x0303, new byte[4]));
        for (int value : new int[]{0, 4, 128, 255}) {
            invalid(replaceCredential(0x0301, new byte[]{(byte) value}));
        }
        for (int value : new int[]{0, 5, 9, 128, 255}) {
            invalid(replaceCredential(0x0302, new byte[]{(byte) value}));
        }
        valid(replace(token, 0x0103, new byte[]{2})); // TOMBSTONE still has every state field.
        for (int value : new int[]{0, 3, 128, 255}) {
            invalid(replace(token, 0x0103, new byte[]{(byte) value}));
        }
    }

    @Test
    void strictUtf8UsesByteLimitsAndPreservesEmptyNulAndUnnormalizedText() {
        String exactBoundary = "a".repeat(252) + "😀";
        for (String text : List.of("", "ASCII", "é水😀", "\u0000", "e\u0301", "é", exactBoundary)) {
            byte[] encoded = text.getBytes(StandardCharsets.UTF_8);
            assertEquals(text, valid(replace(token, 0x0104, encoded)).token().issuer());
            assertEquals(text, valid(replace(token, 0x0105, encoded)).token().account());
            assertEquals(text, valid(replace(device, 0x0202, encoded)).device().displayName());
        }
        assertEquals(256, exactBoundary.getBytes(StandardCharsets.UTF_8).length);
        for (int tag : new int[]{0x0104, 0x0105, 0x0202}) {
            assertEquals(V1PlaintextParser.Reason.INVALID_LENGTH,
                    invalid(replace(tag == 0x0202 ? device : token, tag,
                            ("a" + exactBoundary).getBytes(StandardCharsets.UTF_8))).reason());
        }
    }

    @Test
    void malformedUtf8IsRejectedInsteadOfReplacedAndErrorsDoNotEchoPayloads() {
        // Truncation, bad continuation, overlong NUL, surrogate, >U+10FFFF, lone continuation.
        for (String hex : List.of("c3", "e282", "f09f98", "c328", "c080", "eda080", "f4908080", "80", "ff")) {
            byte[] bytes = HexFormat.of().parseHex(hex);
            for (int tag : new int[]{0x0104, 0x0105, 0x0202}) {
                var result = invalid(replace(tag == 0x0202 ? device : token, tag, bytes));
                assertEquals(V1PlaintextParser.Reason.INVALID_UTF8, result.reason());
                assertEquals("Malformed UTF-8 text", result.message());
            }
        }
        byte[] secret = "never-echo-this-secret".getBytes(StandardCharsets.UTF_8);
        var changed = replaceCredential(0x0304, secret);
        changed = replace(changed, 0x0103, new byte[]{99});
        assertFalse(invalid(changed).message().contains("never-echo"));
        assertEquals("Credential[redacted]", valid(replaceCredential(0x0304, secret)).token().credential().toString());
    }

    @Test
    void intrinsicWidthsAndLegalZeroLengthsAreCheckedBeforeScalarDecoding() {
        for (byte[] sample : List.of(token, device)) {
            for (var tlv : fields(sample)) {
                if (List.of(1, 2, 4, 6, 0x0101, 0x0102, 0x0103, 0x0200, 0x0201).contains(tlv.tag())) {
                    invalid(replace(sample, tlv.tag(), new byte[0]));
                    invalid(replace(sample, tlv.tag(), Arrays.copyOf(tlv.value(), tlv.length() + 1)));
                }
            }
            valid(replace(sample, 0xff01, new byte[0]));
            valid(replace(sample, 0xff01, new byte[72])); // Opaque, not DER validated.
            invalid(replace(sample, 0xff01, new byte[73]));
        }
        for (int tag : new int[]{0x0301, 0x0302, 0x0303}) {
            invalid(replaceCredential(tag, new byte[0]));
            invalid(replaceCredential(tag, new byte[tag == 0x0303 ? 5 : 2]));
        }
        valid(replaceCredential(0x0304, new byte[1]));
        valid(replaceCredential(0x0304, new byte[128]));
        invalid(replaceCredential(0x0304, new byte[0]));
        invalid(replaceCredential(0x0304, new byte[129]));
        // A 65-byte key is structurally opaque; point validity belongs to provenance.
        valid(replace(device, 0x0201, new byte[65]));
    }

    @Test
    void supportedUnknownReservedAndWrongFamilyTagsAreNotOpaqueExtensions() {
        for (int tag : new int[]{0x0003, 0x0100, 0x0107, 0x0201, 0x7fff, 0x8000, 0xffff}) {
            var changed = fields(token);
            changed.add(7, new TlvField(tag, new byte[0]));
            invalid(encode(changed));
        }
        invalid(join(token, field(0xff02)));
        invalid(join(device, field(0xff01)));
        for (int length = 1; length <= 3; length++) {
            assertEquals(V1PlaintextParser.Reason.TRUNCATED_HEADER,
                    invalid(join(token, new byte[length])).reason());
        }
        byte[] badLength = token.clone();
        int body = RoutingParser.parse(token).prefixLength();
        badLength[body + 2] = (byte) 0xff;
        badLength[body + 3] = (byte) 0xff;
        assertEquals(V1PlaintextParser.Reason.TRUNCATED_VALUE, invalid(badLength).reason());
    }

    @Test
    void readerChecksActualSemanticCapacityWithoutWriterSignatureReservation() {
        byte[][] parents = new byte[15][32];
        for (int i = 0; i < parents.length; i++) {
            parents[i][31] = (byte) i;
        }
        byte[] near = parents(replace(token, 0x0104, new byte[256]), parents);
        int padding = 1006 - near.length;
        assertTrue(padding >= 0 && padding < 72);
        byte[] exact = replace(near, 0xff01, new byte[padding]);
        assertEquals(1006, exact.length);
        valid(exact);
        assertEquals(V1PlaintextParser.Reason.SIZE_LIMIT,
                invalid(replace(near, 0xff01, new byte[padding + 1])).reason());
    }

    @Test
    void parsedAndConstructedByteFieldsRemainImmutable() {
        for (byte[] sample : List.of(token, device)) {
            byte[] input = replace(sample, 0xff01, new byte[]{1, 2, 3});
            var result = valid(input);
            byte[] identity = result.routing().identity();
            byte[] retainedBody = result.token() != null
                    ? result.token().credential().secret() : result.device().publicKey();
            Arrays.fill(input, (byte) 0);
            result.signature()[0] = 99;
            assertArrayEquals(new byte[]{1, 2, 3}, result.signature());
            assertArrayEquals(identity, result.routing().identity());
            if (result.token() != null) {
                result.token().credential().secret()[0] ^= 1;
                assertArrayEquals(retainedBody, result.token().credential().secret());
            } else {
                result.device().publicKey()[0] ^= 1;
                assertArrayEquals(retainedBody, result.device().publicKey());
            }
        }
        byte[] data = {1};
        var credential = new V1Plaintext.Credential(1, 6, 1, data);
        var deviceValue = new V1Plaintext.Device(data, "");
        var model = new V1Plaintext(valid(token).routing(), null, deviceValue, data);
        data[0] = 2;
        assertArrayEquals(new byte[]{1}, credential.secret());
        assertArrayEquals(new byte[]{1}, deviceValue.publicKey());
        assertArrayEquals(new byte[]{1}, model.signature());
    }

    @Test
    void futureAndUnknownRoutingNeverEnterTheV1BodyOrCapacityChecks() throws Exception {
        for (var vector : VectorCaseLoader.routingCases()) {
            if (vector.expected().startsWith("OPAQUE_")) {
                var result = V1PlaintextParser.parse(vector.semanticBytes());
                assertEquals(V1PlaintextParser.Status.NOT_SUPPORTED_V1, result.status(), vector.context());
                assertNull(result.plaintext());
                assertEquals(RoutingParser.parse(vector.semanticBytes()).outcome(), result.routing().outcome());
            }
        }
        for (byte[] sample : List.of(token, device)) {
            for (int version : new int[]{0, 2, 255}) {
                byte[] future = replace(sample, 1, new byte[]{(byte) version});
                int end = RoutingParser.parse(future).prefixLength();
                byte[] garbage = new byte[1200];
                Arrays.fill(garbage, (byte) 0xff);
                var result = V1PlaintextParser.parse(join(Arrays.copyOf(future, end), garbage));
                assertEquals(V1PlaintextParser.Status.NOT_SUPPORTED_V1, result.status());
                assertNotNull(result.routing().prefix());
            }
        }
    }

    @Test
    void routingReportsTheExactConsumedLengthEvenForNonzeroSliceOffsets() {
        for (byte[] sample : List.of(token, device, parents(token, new byte[32]))) {
            int expected = (sample[9] == 1 ? 100 : 64) + 36 * (sample[15] & 0xff);
            var parsed = RoutingParser.parse(sample);
            assertEquals(expected, parsed.prefixLength());
            assertEquals(expected, RoutingParser.parse(join(new byte[3], sample), 3, sample.length).prefixLength());
        }
        assertEquals(0, RoutingParser.parse(new byte[0]).prefixLength());
    }

    private static V1Plaintext valid(byte[] bytes) {
        var result = V1PlaintextParser.parse(bytes);
        assertEquals(V1PlaintextParser.Status.STRUCTURALLY_VALID, result.status(), result.message());
        assertNotNull(result.plaintext());
        return result.plaintext();
    }

    private static V1PlaintextParser.Result invalid(byte[] bytes) {
        var result = V1PlaintextParser.parse(bytes);
        assertEquals(V1PlaintextParser.Status.INVALID_STRUCTURE, result.status(), result.message());
        assertNull(result.plaintext());
        assertNotEquals(V1PlaintextParser.Reason.NONE, result.reason());
        return result;
    }

    private static byte[] credential(byte[] bytes) {
        return fields(bytes).stream().filter(f -> f.tag() == 0x0106).findFirst().orElseThrow().value();
    }

    private static byte[] replaceCredential(int tag, byte[] value) {
        return replace(token, 0x0106, replace(credential(token), tag, value));
    }

    private static byte[] parents(byte[] bytes, byte[]... parents) {
        var fields = fields(replace(bytes, 4, new byte[]{0, (byte) parents.length}));
        for (int i = 0; i < parents.length; i++) {
            fields.add(3 + i, new TlvField(5, parents[i]));
        }
        return encode(fields);
    }
}
