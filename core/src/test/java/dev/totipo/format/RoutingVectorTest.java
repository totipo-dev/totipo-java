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

class RoutingVectorTest {
    @Test
    void manifestIncludesExactlyTheSevenPinnedRoutingCases() throws IOException {
        assertEquals(Set.of(
                "v1.routing.device-future-opaque.001", "v1.routing.device-v1.001",
                "v1.routing.future-device-malformed-prefix.001", "v1.routing.future-token-malformed-prefix.001",
                "v1.routing.token-future-opaque.001", "v1.routing.token-v1.001",
                "v1.routing.unknown-type-unscoped.001"),
                VectorCaseLoader.routingCases().stream().map(Case::id).collect(Collectors.toSet()));
    }

    @TestFactory
    List<DynamicTest> pinnedSemanticBytesMeetTheirRoutingExpectations() throws IOException {
        return VectorCaseLoader.routingCases().stream().map(vector -> DynamicTest.dynamicTest(
                vector.context(), () -> check(vector))).toList();
    }

    private static void check(Case vector) {
        byte[] bytes = vector.semanticBytes();
        var result = RoutingParser.parse(bytes);
        switch (vector.expected()) {
            case "SUPPORTED_VALID" -> {
                // This corpus expectation includes later validity. M1.1 asserts ONLY its
                // routing prerequisite; it does not relabel our result SUPPORTED_VALID.
                var input = vector.data().field("input");
                assertEquals(input.field("type").integer().equals(BigInteger.ONE)
                        ? RoutingParser.Outcome.SUPPORTED_V1_TOKEN
                        : RoutingParser.Outcome.SUPPORTED_V1_DEVICE, result.outcome());
                checkFields(input, result.prefix());
            }
            case "OPAQUE_ROUTABLE" -> {
                var input = vector.data().field("future").field("routing");
                assertEquals(input.field("type").integer().equals(BigInteger.ONE)
                        ? RoutingParser.Outcome.OPAQUE_ROUTABLE_TOKEN
                        : RoutingParser.Outcome.OPAQUE_ROUTABLE_DEVICE, result.outcome());
                checkFields(input, result.prefix());
                int size = prefixSize(result.prefix());
                assertArrayEquals(vector.data().field("future").field("opaque_tail_hex").hex(),
                        Arrays.copyOfRange(bytes, size, bytes.length));
            }
            case "OPAQUE_UNSCOPED" -> {
                assertEquals(RoutingParser.Outcome.OPAQUE_UNSCOPED, result.outcome());
                assertNull(result.prefix());
                assertNotEquals(RoutingParser.Reason.NONE, result.reason());
            }
            default -> fail("Unsupported routing expectation: " + vector.expected());
        }
        if (result.prefix() != null) {
            assertEquals(RoutingParser.Reason.NONE, result.reason());
            int size = prefixSize(result.prefix());
            assertEquals(result.outcome(), RoutingParser.parse(Arrays.copyOf(bytes, size)).outcome());
            // Every shortened form of every valid routable vector, deterministically.
            for (int length = 0; length < size; length++) {
                var shortResult = RoutingParser.parse(Arrays.copyOf(bytes, length));
                assertNull(shortResult.prefix(), vector.context() + " length=" + length);
                assertTrue(shortResult.outcome() == RoutingParser.Outcome.MALFORMED
                        || shortResult.outcome() == RoutingParser.Outcome.OPAQUE_UNSCOPED);
                assertEquals(RoutingParser.Reason.TRUNCATED_PREFIX, shortResult.reason());
            }
        }
    }

    private static int prefixSize(RoutingPrefix prefix) {
        return (prefix.objectType() == 1 ? 100 : 64) + 36 * prefix.parents().size();
    }

    static void checkFields(Node expected, RoutingPrefix prefix) {
        assertNotNull(prefix);
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
        if (prefix.objectType() == 1) {
            assertArrayEquals(expected.field("author").base64(), prefix.authorDeviceId());
        } else {
            assertNull(prefix.authorDeviceId());
        }
    }
}
