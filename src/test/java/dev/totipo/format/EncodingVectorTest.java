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
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

class EncodingVectorTest {
    @Test
    void manifestSelectsExactlyTheEightPinnedEncodingCases() throws IOException {
        assertEquals(Set.of("v1.encoding.author-time-u64max.001", "v1.encoding.author-time-zero.001",
                "v1.encoding.device-root.001", "v1.encoding.duplicate-nonrepeatable.001",
                "v1.encoding.parent-count-mismatch.001", "v1.encoding.parent-order.001",
                "v1.encoding.token-root.001", "v1.encoding.utf8-boundary.001"),
                VectorCaseLoader.encodingCases().stream().map(Case::id).collect(Collectors.toSet()));
    }

    @TestFactory
    List<DynamicTest> suppliedSemanticBytesMatchTheirStructuralExpectations() throws IOException {
        return VectorCaseLoader.encodingCases().stream().map(vector -> DynamicTest.dynamicTest(
                vector.context(), () -> check(vector))).toList();
    }

    private static void check(Case vector) {
        byte[] bytes = vector.semanticBytes();
        var result = V1PlaintextParser.parse(bytes);
        switch (vector.expected()) {
            case "SUPPORTED_VALID" -> {
                // Projection onto this milestone: crypto diagnostics and DEVICE_ID
                // derivation are not evaluated, and structural success is not acceptance.
                assertEquals(V1PlaintextParser.Status.STRUCTURALLY_VALID, result.status(), result.message());
                assertEquals(V1PlaintextParser.Reason.NONE, result.reason());
                checkFields(vector.data().field("input"), result.plaintext());
                // The independent pinned bytes, not generated expected bytes, are the oracle.
                assertArrayEquals(bytes, TlvTestBytes.encode(TlvTestBytes.fields(bytes)));
                for (int end = 0; end < bytes.length; end++) {
                    assertEquals(V1PlaintextParser.Status.INVALID_STRUCTURE,
                            V1PlaintextParser.parse(Arrays.copyOf(bytes, end)).status(),
                            vector.context() + " truncated at " + end);
                }
            }
            case "INVALID" -> {
                assertEquals(V1PlaintextParser.Status.INVALID_STRUCTURE, result.status());
                assertNull(result.plaintext());
                assertNotEquals(V1PlaintextParser.Reason.NONE, result.reason());
            }
            default -> fail("Unexpected encoding expectation: " + vector.expected());
        }
    }

    private static void checkFields(Node expected, V1Plaintext actual) {
        var prefix = actual.routing();
        assertEquals(expected.field("version").integer(), BigInteger.valueOf(prefix.version()));
        assertEquals(expected.field("type").integer(), BigInteger.valueOf(prefix.objectType()));
        assertEquals(expected.field("author_time").integer(), prefix.authorTime());
        assertArrayEquals(expected.field("identity").base64(), prefix.identity());
        var parents = expected.field("parents");
        List<Node> values = parents.isNull() ? List.of() : parents.array();
        assertEquals(values.size(), prefix.parents().size());
        for (int i = 0; i < values.size(); i++) {
            assertArrayEquals(values.get(i).base64(), prefix.parents().get(i));
        }
        assertArrayEquals(nullableBytes(expected.field("signature")), actual.signature());
        if (prefix.objectType() == 1) {
            assertNull(actual.device());
            assertArrayEquals(expected.field("author").base64(), prefix.authorDeviceId());
            var token = actual.token();
            assertEquals(expected.field("status").integer(), BigInteger.valueOf(token.status()));
            assertEquals(expected.field("issuer").string(), token.issuer());
            assertEquals(expected.field("account").string(), token.account());
            var credential = token.credential();
            assertEquals(expected.field("algorithm").integer(), BigInteger.valueOf(credential.algorithm()));
            assertEquals(expected.field("digits").integer(), BigInteger.valueOf(credential.digits()));
            assertEquals(expected.field("period").integer(), BigInteger.valueOf(credential.period()));
            assertArrayEquals(expected.field("secret").base64(), credential.secret());
        } else {
            assertNull(actual.token());
            assertNull(prefix.authorDeviceId());
            assertArrayEquals(expected.field("public_key").base64(), actual.device().publicKey());
            assertEquals(expected.field("display_name").string(), actual.device().displayName());
        }
    }

    private static byte[] nullableBytes(Node node) {
        return node.isNull() ? new byte[0] : node.base64();
    }
}
