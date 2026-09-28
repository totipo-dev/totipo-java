package dev.totipo.format;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonToken;
import java.io.IOException;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HexFormat;

/** Small live-file fixture helper; the single pinned corpus remains owned by core. */
final class NioTestFixtures {
    private NioTestFixtures() {}

    static final String TOKEN = "v1.crypto.token-root.001";
    static final String CHILD = "v1.crypto.token-child.001";
    static final String FUTURE = "v1.crypto.future-token-opaque.001";

    record ObjectBytes(ObjectId id, byte[] bytes, byte[] root) {
        @Override public String toString() { return "ObjectBytes[redacted]"; }
    }

    static ObjectBytes fixture(String id) throws IOException {
        String family = id.startsWith("v1.routing.") ? "routing" : "crypto";
        Path file = Path.of(System.getProperty("totipo.test.snapshot"), "vectors", "cases", family, id + ".json");
        var fields = new HashMap<String, String>();
        try (var parser = new JsonFactory().createParser(file.toFile())) {
            while (parser.nextToken() != null) {
                if (parser.currentToken() == JsonToken.VALUE_STRING) {
                    fields.put(parser.currentName(), parser.getText());
                }
            }
        }
        var hex = HexFormat.of();
        return new ObjectBytes(ObjectId.fromFilename(fields.get("object_id")),
                hex.parseHex(fields.get("object_hex")), hex.parseHex(fields.get("root_hex")));
    }

    static DiscoveryResult run(DiscoverySource source, byte[] root) {
        return DiscoveryCoordinator.discover(source, root);
    }
    static TokenOperationPolicy policy(DiscoveryResult result, SecurityBytes token) {
        return new TokenOperationPolicy(result.snapshot(), token);
    }
}
