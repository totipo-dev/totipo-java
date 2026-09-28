package dev.totipo.conformance;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Provenance checks only: this test does not interpret any Totipo protocol bytes. */
class SpecSnapshotIntegrityTest {
    private static final Path ROOT = Path.of("src/test/resources/totipo-spec/v1-pre-rc");
    private static final String CHECKSUMS = "SNAPSHOT.sha256";
    private static final String PROFILE_HASH =
            "e6f11dfd93f64589a88b373009710dad50133d412702c305ad6c20dfc2682895";
    private static final Map<String, String> PINNED = Map.of(
            "spec/totipo-vault-format-v1.md",
            "a60cf63a742b4855b5742e5280ac15cdf6a08e60c81b1a6242b1dea10a1630fb",
            "vectors/manifest.json",
            "2776ed6a8c62609384f0f5e34747b4ce80359fb1abc956137cc64e1ad92def41",
            "vectors/manifest.schema.json",
            "59bdc9165b1c7e940031c447c2da640185774a6e4fd52fa0fee0b245061e0440",
            "vectors/case.schema.json",
            "79e33b68bf948dcc332075827b791c8eb8e54d9cb27634dd59c0c6ac1fd95fd5",
            "requirements/v1-pre-rc.json", PROFILE_HASH);
    private static final Pattern RECORD = Pattern.compile("([0-9a-f]{64})  ([A-Za-z0-9_./-]+)");

    @Test
    void snapshotMatchesChecksumsAndIndependentPins() throws Exception {
        Set<String> paths = verify(ROOT);
        assertEquals(97, paths.size(), "Upstream file count");
        assertEquals(90L, paths.stream().filter(p -> p.startsWith("vectors/cases/")).count());
        for (var pin : PINNED.entrySet()) {
            assertTrue(paths.contains(pin.getKey()), pin.getKey());
            assertEquals(pin.getValue(), sha256(ROOT.resolve(pin.getKey())), pin.getKey());
        }
        List<String> profilePin = Files.readAllLines(Path.of("../SPEC_PIN.md")).stream()
                .filter(line -> line.startsWith("- Profile file SHA-256:")).toList();
        assertEquals(List.of("- Profile file SHA-256: `" + PROFILE_HASH + "`"), profilePin,
                "SPEC_PIN.md must identify the exact vendored profile");
    }

    private static Set<String> verify(Path directory) throws IOException, NoSuchAlgorithmException {
        Path root = directory.toRealPath();
        assertFalse(Files.isSymbolicLink(root.resolve(CHECKSUMS)), "Symlink checksum file");
        Set<String> listed = new HashSet<>();
        String previous = null;
        for (String line : Files.readAllLines(root.resolve(CHECKSUMS))) {
            var match = RECORD.matcher(line);
            assertTrue(match.matches(), "Malformed checksum record: " + line);
            String name = match.group(2);
            Path relative = Path.of(name);
            assertFalse(relative.isAbsolute(), "Absolute path: " + name);
            for (String component : name.split("/", -1)) {
                assertFalse(component.isEmpty() || component.equals(".") || component.equals(".."),
                        "Noncanonical or traversal path: " + name);
            }
            assertFalse(name.equals(CHECKSUMS), "Checksum file must not list itself");
            assertTrue(listed.add(name), "Duplicate path: " + name);
            assertTrue(previous == null || previous.compareTo(name) < 0, "Unsorted path: " + name);
            previous = name;
            Path file = root.resolve(relative).normalize();
            assertTrue(file.startsWith(root), "Path escapes snapshot: " + name);
            // Reject symlinks in every component, including directories.
            Path componentPath = root;
            for (Path component : relative) {
                componentPath = componentPath.resolve(component);
                assertFalse(Files.isSymbolicLink(componentPath), "Symlink: " + name);
            }
            assertTrue(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS), "Missing file: " + name);
            assertTrue(file.toRealPath().startsWith(root), "Real path escapes snapshot: " + name);
            assertEquals(match.group(1), sha256(file), "SHA-256: " + name);
        }
        assertFalse(listed.isEmpty(), "Empty checksum file");
        Set<String> actual = new HashSet<>();
        try (var files = Files.walk(root)) {
            for (Path file : files.toList()) {
                assertFalse(Files.isSymbolicLink(file), "Unexpected symlink: " + file);
                if (Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
                    String name = root.relativize(file).toString().replace('\\', '/');
                    if (!name.equals(CHECKSUMS)) {
                        actual.add(name);
                    }
                }
            }
        }
        assertEquals(listed, actual, "Snapshot contains uncovered files");
        return listed;
    }

    private static String sha256(Path file) throws IOException, NoSuchAlgorithmException {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
    }

    @Test
    void rejectsMalformedDuplicateAndUnsafeRecords(@TempDir Path root) throws Exception {
        Files.writeString(root.resolve("fixture"), "fixture");
        String hash = sha256(root.resolve("fixture"));
        for (String record : List.of(
                "", "bad  fixture", hash.toUpperCase() + "  fixture", hash + " fixture",
                hash + "  /absolute", hash + "  ../escape", hash + "  nested/../fixture",
                hash + "  ./fixture", hash + "  nested//fixture", hash + "  C:/escape",
                hash + "  fixture\n" + hash + "  fixture")) {
            Files.writeString(root.resolve(CHECKSUMS), record + "\n");
            assertThrows(AssertionError.class, () -> verify(root), record);
        }
    }

    @Test
    void rejectsMissingChangedAndUnexpectedFiles(@TempDir Path root) throws Exception {
        Path fixture = root.resolve("fixture");
        Files.writeString(fixture, "original");
        Files.writeString(root.resolve(CHECKSUMS), sha256(fixture) + "  fixture\n");
        verify(root);
        Files.writeString(fixture, "changed");
        assertThrows(AssertionError.class, () -> verify(root));
        Files.delete(fixture);
        assertThrows(AssertionError.class, () -> verify(root));
        Files.writeString(fixture, "original");
        Files.writeString(root.resolve("unexpected"), "extra");
        assertThrows(AssertionError.class, () -> verify(root));
    }
}
