package dev.totipo.conformance;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import org.junit.jupiter.api.Test;

class VectorCaseLoaderTest {
    @Test
    void rejectsMalformedHexAndWrongJsonTypesWithCaseContext() throws IOException {
        for (String value : List.of("\"0\"", "\"gg\"", "\"AA\"", "\"00 1\"", "\"０１\"",
                "null", "42", "true", "[]", "{}")) {
            var node = VectorCaseLoader.parse("{\"hex\":" + value + "}", "case-id (case.json)");
            var failure = assertThrows(IllegalArgumentException.class, () -> node.field("hex").hex());
            assertTrue(failure.getMessage().contains("case-id (case.json).hex"));
        }
        var node = VectorCaseLoader.parse("{\"hex\":\"0080ff\",\"empty\":\"\"}", "case.json");
        assertArrayEquals(new byte[]{0, (byte) 128, (byte) 255}, node.field("hex").hex());
        assertEquals(0, node.field("empty").hex().length);
        node.field("hex").hex()[0] = 99;
        assertEquals(0, node.field("hex").hex()[0]);
    }

    @Test
    void preservesUnsignedJsonIntegersWithoutCoercion() throws IOException {
        var node = VectorCaseLoader.parse("{\"n\":18446744073709551615,\"s\":\"1\",\"a\":null}", "case.json");
        assertEquals(new BigInteger("18446744073709551615"), node.field("n").integer());
        assertThrows(IllegalArgumentException.class, () -> node.field("s").integer());
        assertThrows(IllegalArgumentException.class, () -> node.field("n").string());
        assertThrows(IllegalArgumentException.class, () -> node.field("a").array());
        assertThrows(IllegalArgumentException.class, () -> node.field("missing"));
    }

    @Test
    void rejectsBrokenDuplicateOrTrailingJsonWithResourceContext() {
        for (String json : List.of("", "{", "{\"x\":[", "[]", "{} {}", "{\"x\":1,\"x\":2}", "{\"x\":1.5}")) {
            var error = assertThrows(IOException.class, () -> VectorCaseLoader.parse(json, "case.json"));
            assertTrue(error.getMessage().contains("case.json"));
        }
    }
}
