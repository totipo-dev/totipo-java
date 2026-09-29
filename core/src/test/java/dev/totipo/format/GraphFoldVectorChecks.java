package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader.Case;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Graph evaluation consumes already validated identity/content facts. The same-ID defensive
 * vector exercises an exceptional abstract input and does not claim a constructible
 * cryptographic collision. Symbolic cycles are likewise semantic facts, never fake ciphertext.
 */
final class GraphFoldVectorChecks {
    private GraphFoldVectorChecks() {}

    static void graph(Case vector) {
        assertEquals("PASS", vector.expected());
        shape(vector.data(), Set.of("format", "id", "operation", "expected", "notes", "graph"), Set.of());
        assertEquals("graph", vector.data().field("operation").string());
        shape(vector.data().field("graph"), Set.of("steps"), Set.of());
        var snapshot = new ArrayList<ValidatedToken>();
        var contradictions = new HashSet<ObjectId>();
        int evaluations = 0;
        for (var step : vector.data().field("graph").field("steps").array()) {
            switch (step.field("action").string()) {
                case "add" -> {
                    shape(step, Set.of("action", "node"), Set.of("integrity_error"));
                    var object = symbolicNode(step.field("node"));
                    snapshot.add(object);
                    if (step.has("integrity_error")) {
                        assertTrue(step.field("integrity_error").bool());
                        contradictions.add(object.objectId());
                    }
                    assertEquals(contradictions, TokenGraph.evaluate(snapshot).contradictoryObjectIds());
                }
                case "remove" -> {
                    shape(step, Set.of("action", "id"), Set.of());
                    var id = symbol(step.field("id").string());
                    assertTrue(snapshot.removeIf(object -> object.objectId().equals(id)));
                    contradictions.remove(id);
                }
                case "evaluate" -> {
                    shape(step, Set.of("action", "identity", "expect"), Set.of());
                    var result = TokenGraph.evaluate(snapshot);
                    assertEquals(contradictions, result.contradictoryObjectIds());
                    var view = result.perToken(identity(step.field("identity").string()));
                    var expect = step.field("expect");
                    shape(expect, Set.of("heads", "head_objects", "values", "unresolved", "conflicting"), Set.of());
                    assertEquals(symbols(expect.field("heads")), view.heads().stream()
                            .map(ValidatedToken::objectId).collect(Collectors.toSet()));
                    var expectedObjects = expect.field("head_objects").array().stream()
                            .map(GraphFoldVectorChecks::symbolicNode).collect(Collectors.toSet());
                    assertEquals(expectedObjects, new HashSet<>(view.heads()));
                    assertEquals(expect.field("head_objects").array().size(), view.heads().size());
                    assertEquals(expect.field("values").array().stream().map(n -> value(n.string()))
                            .collect(Collectors.toSet()), view.currentValues());
                    assertEquals(symbols(expect.field("unresolved")), view.unresolvedParents().stream()
                            .map(TokenGraph.UnresolvedParent::parent).collect(Collectors.toSet()));
                    assertEquals(expect.field("conflicting").bool(), view.state() == TokenGraph.CurrentValueState.CONFLICT);
                    evaluations++;
                }
                default -> fail("Unhandled graph action");
            }
        }
        assertTrue(evaluations > 0);
    }

    /** Fixed-length injective encoding for the fixture's ASCII symbols, without hashing. */
    static ObjectId symbol(String symbol) {
        byte[] text = symbol.getBytes(StandardCharsets.US_ASCII);
        assertTrue(symbol.matches("[A-Za-z0-9]+") && text.length <= 31);
        byte[] bytes = Arrays.copyOf(text, 32);
        bytes[31] = (byte) text.length;
        return new ObjectId(bytes);
    }

    static TokenId identity(String symbol) { return new TokenId(symbol(symbol).bytes()); }

    // X/Y/Z/W are abstract whole-value labels, mapped injectively to complete valid tuples.
    static TokenValue value(String label) {
        return new TokenValue(1, label, "account",
                new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{42}, 1)));
    }

    static TokenMetadata metadata(Node node) {
        return new TokenMetadata(node.has("client_name") ? Optional.of(node.field("client_name").string()) : Optional.empty(),
                node.has("client_time") ? Optional.of(new UInt64(Long.parseUnsignedLong(
                        node.field("client_time").integer().toString()))) : Optional.empty());
    }

    private static ValidatedToken symbolicNode(Node node) {
        shape(node, Set.of("id", "identity", "parents", "canonical", "value"), Set.of("client_name", "client_time"));
        var parents = node.field("parents").isNull() ? List.<String>of()
                : node.field("parents").array().stream().map(Node::string).toList();
        // 'canonical' is a symbolic fixture assertion, not serialized P. Check its complete
        // label against the supplied facts so differences cannot be silently discarded.
        String canonical = node.field("id").string() + "/" + node.field("identity").string()
                + "/" + node.field("value").string() + "/" + String.join(",", parents);
        if (node.has("client_name") || node.has("client_time")) {
            // Current graph fixtures use plain ASCII names; reject new syntax for explicit review.
            String name = node.has("client_name") ? node.field("client_name").string() : "";
            assertTrue(name.matches("[A-Za-z]*"));
            canonical += "/metadata/\"" + name + "\"/"
                    + (node.has("client_time") ? node.field("client_time").integer().toString() : "");
        }
        assertEquals(canonical, node.field("canonical").string());
        return new ValidatedToken(symbol(node.field("id").string()),
                new TokenObject(identity(node.field("identity").string()),
                        parents.stream().map(GraphFoldVectorChecks::symbol).sorted(TokenGraph.OBJECT_ORDER).toList(),
                        value(node.field("value").string()), metadata(node)));
    }

    private static Set<ObjectId> symbols(Node node) {
        return node.array().stream().map(n -> symbol(n.string())).collect(Collectors.toSet());
    }

    static void fold(Case vector) {
        assertEquals("PASS", vector.expected());
        shape(vector.data(), Set.of("format", "id", "operation", "expected", "notes", "fold"), Set.of());
        assertEquals("fold", vector.data().field("operation").string());
        var fold = vector.data().field("fold");
        shape(fold, Set.of("token", "frontier", "stage_ids", "parents"), Set.of());
        var input = fold.field("token");
        shape(input, Set.of("identity", "parents", "status", "issuer", "account", "algorithm", "digits", "period", "secret"),
                Set.of("client_name", "client_time"));
        assertTrue(input.field("parents").array().isEmpty());
        var tokenId = new TokenId(input.field("identity").base64());
        byte[] secret = input.field("secret").base64();
        var value = new TokenValue(input.field("status").integer().intValueExact(), input.field("issuer").string(),
                input.field("account").string(), new TokenValue.Credential(input.field("algorithm").integer().intValueExact(),
                input.field("digits").integer().intValueExact(), input.field("period").integer().longValueExact(),
                new SecurityBytes(secret, secret.length)));
        var metadata = metadata(input);
        var frontier = fold.field("frontier").array().stream().map(n -> ObjectId.fromFilename(n.string())).toList();
        var stages = TokenFold.build(tokenId, frontier, value, metadata, new byte[32]);
        var expectedParents = fold.field("parents").array();
        var symbolicIds = fold.field("stage_ids").array();
        assertEquals(expectedParents.size(), stages.size());
        assertEquals(symbolicIds.size(), stages.size());
        var actualIds = new HashMap<ObjectId, ObjectId>();
        var graph = new ArrayList<ValidatedToken>();
        for (var id : frontier) graph.add(new ValidatedToken(id, new TokenObject(tokenId, List.of(), value, metadata)));
        for (int i = 0; i < stages.size(); i++) {
            var stage = stages.get(i);
            // Substitute only preceding symbolic stage IDs with real HMAC identities.
            var parents = expectedParents.get(i).array().stream().map(n -> ObjectId.fromFilename(n.string()))
                    .map(id -> actualIds.getOrDefault(id, id)).sorted(TokenGraph.OBJECT_ORDER).toList();
            assertEquals(parents, stage.token().parents());
            assertEquals(tokenId, stage.token().tokenId());
            assertEquals(value, stage.token().value());
            assertEquals(metadata, stage.token().metadata());
            assertNull(actualIds.put(ObjectId.fromFilename(symbolicIds.get(i).string()), stage.objectId()));
            var sealed = V1EnvelopeWriter.seal(new byte[32], TokenWriter.write(stage.token()));
            assertEquals(stage.objectId(), sealed.id());
            var opened = EnvelopeReader.open(sealed.id().filename(), sealed.bytes(), new byte[32]);
            assertEquals(EnvelopeReader.Status.AUTHENTICATED_SEMANTIC, opened.status());
            assertEquals(stage.token(), TokenReader.read(opened.semanticBytes()));
            graph.add(new ValidatedToken(stage.objectId(), stage.token()));
        }
        var last = stages.get(stages.size() - 1);
        var view = TokenGraph.evaluate(graph).perToken(tokenId);
        assertEquals(List.of(new ValidatedToken(last.objectId(), last.token())), view.heads());
        assertTrue(view.unresolvedParents().isEmpty());
        assertEquals(Set.of(value), view.currentValues());
    }

    private static void shape(Node node, Set<String> required, Set<String> optional) {
        var allowed = new HashSet<>(required);
        allowed.addAll(optional);
        assertTrue(node.fieldNames().containsAll(required), "Missing fixture fields");
        assertTrue(allowed.containsAll(node.fieldNames()), "Unhandled fixture fields: " + node.fieldNames());
    }
}
