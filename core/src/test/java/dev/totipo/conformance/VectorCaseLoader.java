package dev.totipo.conformance;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.core.StreamReadFeature;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Small test-only JSON tree backed by Jackson's streaming tokenizer; no type coercion. */
public final class VectorCaseLoader {
    private static final String ROOT = "/totipo-spec/v1-pre-rc/vectors/";
    private static final JsonFactory JSON = JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    private VectorCaseLoader() {}

    public record Case(String id, String path, String expected, Node data) {
        public byte[] semanticBytes() {
            return data.field("semantic_hex").hex();
        }

        public String context() {
            return id + " (" + path + ")";
        }
    }

    public static List<Case> routingCases() throws IOException {
        return cases("routing");
    }

    public static List<Case> encodingCases() throws IOException {
        return cases("encoding");
    }

    public static List<Case> cryptoCases() throws IOException {
        return cases("crypto");
    }

    public static List<Case> provenanceCases() throws IOException { return cases("provenance"); }

    public static List<Case> deviceCases() throws IOException { return cases("device"); }
    public static List<Case> bootstrapCases() throws IOException { return cases("bootstrap"); }
    public static List<Case> totpCases() throws IOException { return cases("totp"); }
    public static List<Case> graphCases() throws IOException { return cases("graph"); }
    public static List<Case> futureCases() throws IOException { return cases("future"); }
    public static List<Case> timestampCases() throws IOException { return cases("timestamp"); }
    public static List<Case> candidateCases() throws IOException { return cases("candidate"); }
    public static List<Case> storageCases() throws IOException { return cases("storage"); }

    private static List<Case> cases(String category) throws IOException {
        Node manifest = resource("manifest.json");
        if (!manifest.field("format").string().equals("totipo-vector-manifest-v1")) {
            throw manifest.error("Unexpected manifest format");
        }
        List<Case> cases = new ArrayList<>();
        var ids = new HashSet<String>();
        for (Node entry : manifest.field("cases").array()) {
            if (!entry.field("category").string().equals(category)) {
                continue;
            }
            String id = entry.field("id").string();
            String path = entry.field("path").string();
            if (!path.matches("cases/" + category + "/[a-z0-9.-]+\\.json")) {
                throw entry.error(id + ": unsafe case path " + path);
            }
            if (!ids.add(id)) {
                throw entry.error("Duplicate case ID " + id);
            }
            Node data;
            try {
                data = resource(path);
            } catch (IOException e) {
                throw new IOException(id + " (" + path + "): " + e.getMessage(), e);
            }
            data = new Node(data.value, id + " (" + path + ")");
            String expected = data.field("expected").string();
            if (!data.field("id").string().equals(id)
                    || !entry.field("expected").string().equals(expected)
                    || !data.field("format").string().equals("totipo-case-v1")
                    || !(data.field("operation").string().equals("dispatch")
                        || (category.equals("crypto") && data.field("operation").string().equals("crypto"))
                        || (category.equals("bootstrap") && data.field("operation").string().equals("bootstrap"))
                        || (category.equals("totp") && data.field("operation").string().equals("totp"))
                        || (category.equals("device") && data.field("operation").string().equals("graph"))
                        || (category.equals("graph") && data.field("operation").string().equals("graph"))
                        || (category.equals("storage") && data.field("operation").string().equals("storage"))
                        || (category.equals("candidate") && data.field("operation").string().equals("graph"))
                        || (category.equals("timestamp") && java.util.Set.of("graph", "dispatch")
                            .contains(data.field("operation").string()))
                        || (category.equals("future") && java.util.Set.of("graph", "opaque-retention", "storage")
                            .contains(data.field("operation").string()))
                        || (category.equals("provenance") && java.util.Set.of("provenance", "publication",
                            "signature-context", "late-provenance").contains(data.field("operation").string())))) {
                throw data.error("Manifest/case identity, expected value, or format mismatch");
            }
            cases.add(new Case(id, path, expected, data));
        }
        return List.copyOf(cases);
    }

    private static Node resource(String path) throws IOException {
        try (InputStream in = VectorCaseLoader.class.getResourceAsStream(ROOT + path)) {
            if (in == null) {
                throw new IOException(path + ": resource missing");
            }
            try (JsonParser parser = JSON.createParser(in)) {
                return parse(parser, path);
            }
        }
    }

    static Node parse(String json, String context) throws IOException {
        try (JsonParser parser = JSON.createParser(json)) {
            return parse(parser, context);
        }
    }

    private static Node parse(JsonParser parser, String context) throws IOException {
        try {
            parser.nextToken();
            Object value = read(parser);
            if (parser.nextToken() != null) {
                throw new IOException("Trailing JSON value");
            }
            if (!(value instanceof Map<?, ?>)) {
                throw new IOException("Expected object root");
            }
            return new Node(value, context);
        } catch (IOException e) {
            throw new IOException(context + ": " + e.getMessage(), e);
        }
    }

    private static Object read(JsonParser parser) throws IOException {
        JsonToken token = parser.currentToken();
        if (token == null) {
            throw new IOException("Missing JSON value");
        }
        switch (token) {
            case START_OBJECT: {
                Map<String, Object> fields = new LinkedHashMap<>();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    if (parser.currentToken() != JsonToken.FIELD_NAME) {
                        throw new IOException("Expected field name");
                    }
                    String name = parser.currentName();
                    parser.nextToken();
                    fields.put(name, read(parser));
                }
                return Collections.unmodifiableMap(fields);
            }
            case START_ARRAY: {
                List<Object> values = new ArrayList<>();
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    values.add(read(parser));
                }
                return Collections.unmodifiableList(values);
            }
            case VALUE_STRING: return parser.getText();
            case VALUE_NUMBER_INT: return parser.getBigIntegerValue();
            case VALUE_TRUE: return Boolean.TRUE;
            case VALUE_FALSE: return Boolean.FALSE;
            case VALUE_NULL: return null;
            default: throw new IOException("Unsupported JSON token " + token);
        }
    }

    public static final class Node {
        private final Object value;
        private final String context;

        private Node(Object value, String context) {
            this.value = value;
            this.context = context;
        }

        public Node field(String name) {
            if (!(value instanceof Map<?, ?> fields) || !fields.containsKey(name)) {
                throw error("Missing required object field " + name);
            }
            return new Node(fields.get(name), context + "." + name);
        }

        public boolean has(String name) {
            return value instanceof Map<?, ?> fields && fields.containsKey(name);
        }

        public boolean bool() {
            if (!(value instanceof Boolean result)) { throw error("Expected boolean"); }
            return result;
        }

        public boolean isNull() {
            return value == null;
        }

        public String string() {
            if (!(value instanceof String text)) {
                throw error("Expected string");
            }
            return text;
        }

        public BigInteger integer() {
            if (!(value instanceof BigInteger integer)) {
                throw error("Expected integer");
            }
            return integer;
        }

        public List<Node> array() {
            if (!(value instanceof List<?> elements)) {
                throw error("Expected array");
            }
            List<Node> result = new ArrayList<>();
            for (int i = 0; i < elements.size(); i++) {
                result.add(new Node(elements.get(i), context + "[" + i + "]"));
            }
            return List.copyOf(result);
        }

        public byte[] hex() {
            String hex = string();
            if ((hex.length() & 1) != 0 || !hex.matches("[0-9a-f]*")) {
                throw error("Expected even-length lowercase hexadecimal");
            }
            return HexFormat.of().parseHex(hex);
        }

        public byte[] base64() {
            String text = string();
            try {
                byte[] decoded = Base64.getDecoder().decode(text);
                if (!Base64.getEncoder().encodeToString(decoded).equals(text)) {
                    throw error("Expected canonical padded base64");
                }
                return decoded;
            } catch (IllegalArgumentException e) {
                throw error("Invalid base64");
            }
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(context + ": " + message);
        }
    }
}
