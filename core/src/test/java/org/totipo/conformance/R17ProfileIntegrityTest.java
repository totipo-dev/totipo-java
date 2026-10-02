package org.totipo.conformance;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** Pins corpus/profile integrity, not implementation coverage of its semantic cases. */
class R17ProfileIntegrityTest {
    @Test void movingProfileRequiresExactlyThePhysicalManifestCases() throws Exception {
        Path root = Path.of("src/test/resources/totipo-spec/v1-pre-rc");
        var manifest = VectorCaseLoader.parse(Files.readString(root.resolve("vectors/manifest.json")), "manifest");
        var profile = VectorCaseLoader.parse(Files.readString(root.resolve("requirements/v1-pre-rc.json")), "profile");
        assertEquals("totipo-vector-manifest-v1", manifest.field("format").string());
        assertEquals("totipo-requirements-v1", profile.field("format").string());
        assertEquals("moving-pre-rc", profile.field("status").string());
        assertEquals("totipo-v1", manifest.field("protocol").string());
        assertEquals("totipo-v1", profile.field("protocol").string());
        assertEquals("r17", manifest.field("spec_revision").string());
        assertEquals("r17", profile.field("spec_revision").string());
        for (var pin : java.util.Map.of("spec_sha256", "spec/totipo-vault-format-v1.md",
                "manifest_sha256", "vectors/manifest.json", "schema_sha256", "vectors/manifest.schema.json",
                "case_schema_sha256", "vectors/case.schema.json").entrySet()) {
            assertEquals(profile.field(pin.getKey()).string(), hash(root.resolve(pin.getValue())));
        }
        var required = new HashMap<String, String>();
        for (var entry : profile.field("required_cases").array()) {
            assertNull(required.put(entry.field("id").string(), entry.field("sha256").string()));
        }
        var listed = new HashMap<String, String>();
        var paths = new HashSet<String>();
        var categories = new HashSet<String>();
        assertEquals(90, manifest.field("cases").array().size());
        for (var entry : manifest.field("cases").array()) {
            assertTrue(entry.field("normative").bool());
            assertFalse(entry.field("spec_sections").array().isEmpty());
            String category = entry.field("category").string();
            categories.add(category);
            String path = entry.field("path").string();
            assertTrue(path.matches("cases/[a-z]+/[a-z0-9.-]+\\.json"));
            assertTrue(path.startsWith("cases/" + category + "/"));
            assertTrue(paths.add(path));
            String sha = entry.field("sha256").string();
            assertNull(listed.put(entry.field("id").string(), sha));
            assertEquals(sha, hash(root.resolve("vectors").resolve(path)), path);
            assertTrue(Set.of("bytes", "negative", "semantic").contains(entry.field("kind").string()));
        }
        assertEquals(90, required.size());
        assertEquals(required, listed);
        assertEquals(Set.of("bootstrap", "crypto", "encoding", "fold", "graph", "metadata", "size",
                "storage", "totp", "vault"), categories);
        var loaded = VectorCaseLoader.allCases();
        assertEquals(90, loaded.size());
        assertEquals(listed.keySet(), loaded.stream().map(VectorCaseLoader.Case::id)
                .collect(java.util.stream.Collectors.toSet()));
        for (String category : categories) {
            assertEquals(paths.stream().filter(p -> p.startsWith("cases/" + category + "/")).count(),
                    VectorCaseLoader.cases(category).size());
        }
        try (var files = Files.walk(root.resolve("vectors/cases"))) {
            assertEquals(paths, files.filter(Files::isRegularFile)
                    .map(p -> root.resolve("vectors").relativize(p).toString())
                    .collect(java.util.stream.Collectors.toSet()));
        }
    }

    private static String hash(Path path) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
    }
}
