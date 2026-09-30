package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Node;
import dev.totipo.storage.nio.NioDiscoverySource;
import dev.totipo.storage.nio.NioDurability;
import dev.totipo.storage.nio.ObjectPublicationFaults;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

/** Single storage interpretation shared by inventory and dynamic cases. */
final class StorageVectorChecks {
    private StorageVectorChecks() {}

    static void check(VectorCaseLoader.Case vector) throws Exception {
        assertEquals("PASS", vector.expected());
        switch (vector.data().field("operation").string()) {
            case "storage" -> observe(vector);
            case "workflow" -> publish(vector);
            default -> fail("Unknown storage operation: " + vector.context());
        }
    }

    private static void fields(Node node, String... names) { assertEquals(Set.of(names), node.fieldNames()); }

    private static void observe(VectorCaseLoader.Case vector) throws Exception {
        fields(vector.data(), "format", "id", "operation", "expected", "root_hex", "storage");
        var fixture = vector.data().field("storage");
        fields(fixture, "namespace_kind", "entries", "classes", "diagnostics");
        assertEquals("directory", fixture.field("namespace_kind").string());
        byte[] root = vector.data().field("root_hex").hex();
        var classes = new ArrayList<String>();
        var validated = new ArrayList<ValidatedToken>();
        boolean unavailable = false;
        // Entries describe observations, including repeated paths with different bytes.
        // Materialize each in an isolated test directory, never open a corpus path directly.
        for (var entry : fixture.field("entries").array()) {
            if (entry.has("unreadable")) fields(entry, "path", "kind", "object_hex", "unreadable");
            else fields(entry, "path", "kind", "object_hex");
            assertEquals("regular", entry.field("kind").string());
            String path = entry.field("path").string();
            assertTrue(path.matches("objects-v[12]/[a-f0-9]{64}(\\.tmp)?"), "Unhandled fixture path");
            String[] parts = path.split("/");
            Path directory = Files.createTempDirectory("totipo-storage-vector-");
            try {
                Files.createDirectory(directory.resolve("objects-v1"));
                Files.createDirectories(directory.resolve(parts[0]));
                Path target = directory.resolve(parts[0]).resolve(parts[1]);
                Files.write(target, entry.field("object_hex").hex());
                boolean failsRead = entry.has("unreadable") && entry.field("unreadable").bool();
                var opened = new ArrayList<ObjectId>();
                DiscoverySource source = () -> {
                    var snapshot = new NioDiscoverySource(directory).snapshot();
                    return new DiscoverySource.Snapshot(snapshot.candidates().stream().map(c ->
                            new DiscoverySource.Candidate(c.id(), () -> {
                                opened.add(c.id());
                                if (failsRead) throw new IOException("Injected unavailable read");
                                return c.opener().open();
                            })).toList(), snapshot.issue(), snapshot);
                };
                var result = TokenStoreReader.read(source, root);
                boolean candidate = parts[0].equals("objects-v1") && parts[1].length() == 64;
                assertEquals(candidate ? List.of(ObjectId.fromFilename(parts[1])) : List.of(), opened);
                assertTrue(result.snapshotDiagnostics().isEmpty());
                for (var diagnostic : result.candidateDiagnostics()) {
                    switch (diagnostic.reason()) {
                        case INVALID_STORAGE -> classes.add("INVALID_STORAGE");
                        case INVALID_TOKEN -> classes.add("INVALID");
                        case UNAVAILABLE -> unavailable = true;
                    }
                }
                for (var token : result.validatedTokens()) {
                    classes.add("SUPPORTED_VALID");
                    validated.add(token);
                    var expected = EnvelopeReader.open(parts[1], entry.field("object_hex").hex(), root);
                    byte[] semantic = expected.semanticBytes();
                    try { assertEquals(TokenReader.read(semantic), token.token()); }
                    finally { Arrays.fill(semantic, (byte) 0); expected.clear(); }
                    assertEquals(parts[1], token.objectId().filename());
                }
                if (!result.validatedTokens().isEmpty()) {
                    assertEquals(result.validatedTokens(), TokenGraph.evaluate(result.validatedTokens())
                            .perToken(result.validatedTokens().get(0).token().tokenId()).objects());
                }
            } finally { deleteTree(directory); }
        }
        assertEquals(fixture.field("classes").array().stream().map(Node::string).toList(), classes);
        assertEquals(fixture.field("diagnostics").bool(), unavailable);
        assertEquals(classes.stream().filter("SUPPORTED_VALID"::equals).count(), validated.size());
        if (unavailable) assertFalse(TokenGraph.evaluate(validated).perToken().isEmpty());
    }

    private static void publish(VectorCaseLoader.Case vector) throws Exception {
        fields(vector.data(), "format", "id", "operation", "expected", "workflow");
        var fixture = vector.data().field("workflow");
        fields(fixture, "action", "kind", "existing_hex", "intended_hex", "base_hex", "readable",
                "complete", "durable", "orphan_objects", "parents_available", "result");
        assertEquals("publish", fixture.field("action").string());
        // These fields describe bootstrap/replace inputs, not prerequisites for publish.
        assertArrayEquals(new byte[0], fixture.field("base_hex").hex());
        assertFalse(fixture.field("readable").bool());
        assertFalse(fixture.field("orphan_objects").bool());
        assertTrue(fixture.field("complete").bool());
        byte[] intended = fixture.field("intended_hex").hex();
        assertEquals(1024, intended.length);
        byte[] existing = fixture.field("existing_hex").hex();
        boolean durable = fixture.field("durable").bool();
        boolean parentsAvailable = fixture.field("parents_available").bool();
        String expected = fixture.field("result").string();
        assertTrue(Set.of("PUBLISHED_NEW", "ALREADY_PRESENT_EXACT", "FAILED").contains(expected));
        // Match the exact intended object to pinned crypto fixtures to recover its root/ID.
        var crypto = VectorCaseLoader.cryptoCases().stream().filter(v -> v.data().has("crypto")
                && Arrays.equals(v.data().field("crypto").field("object_hex").hex(), intended)).findFirst().orElseThrow();
        byte[] root = crypto.data().field("root_hex").hex();
        ObjectId id = ObjectId.fromFilename(crypto.data().field("crypto").field("object_id").string());
        var token = TokenReader.read(crypto.semanticBytes());
        var plan = TokenPublicationPlan.planAssertion(token.tokenId(), token.parents(), token.value(), token.metadata(), root);
        assertEquals(id, plan.stages().get(0).objectId());
        String kind = fixture.field("kind").string();
        assertTrue(Set.of("absent", "regular", "unreadable").contains(kind));
        if (kind.equals("absent") && !durable) {
            assertArrayEquals(new byte[0], existing);
            // Deterministic SPI simulation of the two possible ambiguous residues.
            for (boolean residue : List.of(false, true)) {
                var store = new PublicationTestStore();
                store.failCall = 1; store.installOnFailure = residue;
                assertThrows(IOException.class, () -> TokenPublisher.publish(plan, root, store));
                assertEquals("FAILED", expected);
                assertEquals(residue, store.objects.containsKey(id));
                assertEquals(1, store.calls);
                store.failCall = -1;
                assertEquals(List.of(residue ? V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT
                        : V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW), TokenPublisher.publish(plan, root, store));
                assertArrayEquals(intended, store.objects.get(id));
            }
            return;
        }
        Path directory = Files.createTempDirectory("totipo-publication-vector-");
        try {
            Path namespace = directory.resolve("objects-v1");
            Path target = namespace.resolve(id.filename());
            if (!kind.equals("absent")) {
                Files.createDirectory(namespace);
                Files.write(target, existing);
            } else assertArrayEquals(new byte[0], existing);
            if (parentsAvailable) {
                for (var parent : token.parents()) {
                    var parentFixture = VectorCaseLoader.cryptoCases().stream().filter(v -> v.data().has("crypto")
                            && v.data().field("crypto").field("object_id").string().equals(parent.filename())).findFirst().orElseThrow();
                    Files.createDirectories(namespace);
                    Files.write(namespace.resolve(parent.filename()), parentFixture.data().field("crypto").field("object_hex").hex());
                }
            } else for (var parent : token.parents()) assertFalse(Files.exists(namespace.resolve(parent.filename())));
            var faults = new ObjectPublicationFaults(path -> {
                assertTrue(durable, "Exact-existing must not request persistence");
                new NioDurability().syncDirectory(path);
            });
            if (kind.equals("unreadable")) faults.fail = "existing-read";
            String actual;
            try (var store = faults.open(directory)) {
                try { actual = TokenPublisher.publish(plan, root, store).get(0).name(); }
                catch (IOException failed) { actual = "FAILED"; }
            }
            assertEquals(expected, actual);
            if (kind.equals("absent")) {
                assertArrayEquals(intended, Files.readAllBytes(target));
                assertTrue(faults.events.indexOf("stage-sync") < faults.events.indexOf("before-link"));
                assertTrue(faults.events.contains("directory-sync"));
                var observation = TokenStoreReader.read(new NioDiscoverySource(directory), root);
                assertTrue(observation.validatedTokens().contains(new ValidatedToken(id, token)));
                var view = TokenGraph.evaluate(observation.validatedTokens()).perToken(token.tokenId());
                assertEquals(List.of(new ValidatedToken(id, token)), view.heads());
                if (!parentsAvailable) assertEquals(token.parents(), view.unresolvedParents().stream()
                        .map(TokenGraph.UnresolvedParent::parent).toList());
            } else {
                assertArrayEquals(existing, Files.readAllBytes(target));
                assertEquals(List.of("snapshot", "mkdir", "existing-read"), faults.events);
            }
        } finally { deleteTree(directory); }
    }

    static void deleteTree(Path directory) throws IOException {
        try (var paths = Files.walk(directory)) {
            for (var path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        }
    }
}
