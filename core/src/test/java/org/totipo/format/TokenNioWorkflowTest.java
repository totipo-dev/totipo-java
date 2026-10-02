package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static org.totipo.format.V1ObjectPublicationStore.PublicationResult.*;

import org.totipo.storage.nio.NioDiscoverySource;
import org.totipo.storage.nio.NioDurability;
import org.totipo.storage.nio.NioV1ObjectPublicationStore;
import org.totipo.storage.nio.ObjectPublicationFaults;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TokenNioWorkflowTest {
    @ParameterizedTest @ValueSource(booleans = {false, true})
    void alternateCaseEncryptedObjectNeverAcknowledgesExactAndCanonicalRetryIsDiscoverable(boolean mixed) throws Exception {
        Path directory = directory();
        try {
            var plan = TokenPublicationTest.plan(0);
            var stage = plan.stages().get(0);
            var sealed = V1EnvelopeWriter.seal(TokenPublicationTest.root(), TokenWriter.write(stage.token()));
            assertEquals(stage.objectId(), sealed.id());
            String name = sealed.id().filename();
            String alias = name.toUpperCase(java.util.Locale.ROOT);
            if (mixed) {
                int letter = 0;
                while (Character.isDigit(name.charAt(letter))) letter++;
                alias = name.substring(0, letter) + Character.toUpperCase(name.charAt(letter)) + name.substring(letter + 1);
            }
            assertNotEquals(name, alias);
            Path namespace = Files.createDirectory(directory.resolve("objects-v1"));
            Path sibling = Files.write(namespace.resolve(alias), sealed.bytes());
            var before = Files.readAttributes(sibling, BasicFileAttributes.class);
            assertTrue(read(directory).validatedTokens().isEmpty());
            try (var store = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
                assertEquals(PUBLISHED_NEW, store.publish(sealed.id(), sealed.bytes()));
            }
            try (var store = NioV1ObjectPublicationStore.open(directory, path -> fail("Exact retry must remain read-only"))) {
                assertEquals(ALREADY_PRESENT_EXACT, store.publish(sealed.id(), sealed.bytes()));
            }
            try (var snapshot = new NioDiscoverySource(directory).snapshot()) {
                assertEquals(List.of(sealed.id()), snapshot.candidates().stream().map(DiscoverySource.Candidate::id).toList());
            }
            assertEquals(List.of(new ValidatedToken(stage.objectId(), stage.token())), read(directory).validatedTokens());
            assertArrayEquals(sealed.bytes(), Files.readAllBytes(sibling));
            var after = Files.readAttributes(sibling, BasicFileAttributes.class);
            assertEquals(before.fileKey(), after.fileKey());
            assertEquals(before.lastModifiedTime(), after.lastModifiedTime());
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    private static Path directory() throws IOException {
        return Files.createTempDirectory(Path.of("build"), "token-workflow-").toAbsolutePath();
    }
    private static TokenStoreObservation read(Path directory) {
        return TokenStoreReader.read(new NioDiscoverySource(directory), TokenPublicationTest.root());
    }
    private static void publish(Path directory, TokenPublicationPlan plan) throws IOException {
        try (var store = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
            assertEquals(Collections.nCopies(plan.stages().size(), PUBLISHED_NEW),
                    TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
        }
    }
    private static void checkFiles(Path directory, TokenPublicationPlan plan) throws IOException {
        for (var stage : plan.stages()) {
            Path target = directory.resolve("objects-v1").resolve(stage.objectId().filename());
            assertEquals(1024, Files.size(target));
            assertTrue(read(directory).validatedTokens().contains(new ValidatedToken(stage.objectId(), stage.token())));
        }
    }

    @Test void namespaceSelectionDoesNotTraverseSiblingsNestedDirectoriesOrSymlinks() throws Exception {
        Path directory = directory();
        try {
            var plan = TokenPublicationTest.plan(0); publish(directory, plan);
            var stage = plan.stages().get(0);
            Path namespace = directory.resolve("objects-v1");
            byte[] bytes = Files.readAllBytes(namespace.resolve(stage.objectId().filename()));
            Path sibling = Files.createDirectory(directory.resolve("objects-v2"));
            Files.write(sibling.resolve(stage.objectId().filename()), bytes);
            Path nested = Files.createDirectory(namespace.resolve("nested"));
            Files.write(nested.resolve(stage.objectId().filename()), bytes);
            Files.write(namespace.resolve(stage.objectId().filename() + ".tmp"), bytes);
            Files.write(namespace.resolve(stage.objectId().filename().toUpperCase(java.util.Locale.ROOT)), bytes);
            Files.createSymbolicLink(namespace.resolve("f".repeat(64)), sibling.resolve(stage.objectId().filename()));
            var result = read(directory);
            assertEquals(List.of(new ValidatedToken(stage.objectId(), stage.token())), result.validatedTokens());
            assertTrue(result.candidateDiagnostics().isEmpty());
            assertTrue(result.snapshotDiagnostics().isEmpty());
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    @Test void newUpdateCloseReopenAndMissingParent() throws Exception {
        Path directory = directory();
        try {
            assertEquals(List.of(), read(directory).validatedTokens());
            assertFalse(Files.exists(directory.resolve("objects-v1")));
            var initial = TokenPublicationPlan.planNew(TokenPublicationTest.value(1, "initial"), TokenPublicationTest.metadata(),
                    bytes -> Arrays.fill(bytes, (byte) 42), TokenPublicationTest.root());
            publish(directory, initial); checkFiles(directory, initial);
            var first = initial.stages().get(0);
            var view = TokenGraph.evaluate(read(directory).validatedTokens()).perToken(first.token().tokenId());
            assertEquals(List.of(new ValidatedToken(first.objectId(), first.token())), view.heads());
            assertEquals(1, view.currentGroups().size());
            var update = TokenPublicationPlan.planAssertion(first.token().tokenId(), List.of(first.objectId()),
                    TokenPublicationTest.value(2, "updated"), TokenPublicationTest.metadata(), TokenPublicationTest.root());
            publish(directory, update); checkFiles(directory, update);
            view = TokenGraph.evaluate(read(directory).validatedTokens()).perToken(first.token().tokenId());
            var second = update.stages().get(0);
            assertEquals(List.of(new ValidatedToken(second.objectId(), second.token())), view.heads());
            assertEquals(2, view.objects().size());
            assertTrue(view.unresolvedParents().isEmpty());
            // Explicitly claim an absent parent along with the known head; restore is ordinary LIVE.
            var missing = TokenPublicationTest.parents(1).get(0);
            var restore = TokenPublicationPlan.planAssertion(first.token().tokenId(), List.of(second.objectId(), missing),
                    TokenPublicationTest.value(1, "restored"), TokenPublicationTest.metadata(), TokenPublicationTest.root());
            publish(directory, restore); checkFiles(directory, restore);
            view = TokenGraph.evaluate(read(directory).validatedTokens()).perToken(first.token().tokenId());
            var third = restore.stages().get(0);
            assertEquals(List.of(new ValidatedToken(third.objectId(), third.token())), view.heads());
            assertEquals(List.of(new TokenGraph.UnresolvedParent(third.objectId(), missing)), view.unresolvedParents());
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    @ParameterizedTest @ValueSource(ints = {5, 11})
    void wideFrontierUsesOrdinaryGraphSemanticsAndExactRetries(int width) throws Exception {
        Path directory = directory();
        try {
            for (int i = 0; i < width; i++) publish(directory, TokenPublicationPlan.planAssertion(TokenPublicationTest.tokenId(),
                    List.of(), TokenPublicationTest.value(1, "branch-" + i), TokenPublicationTest.metadata(), TokenPublicationTest.root()));
            var before = TokenGraph.evaluate(read(directory).validatedTokens()).perToken(TokenPublicationTest.tokenId());
            assertEquals(width, before.heads().size());
            var explicitParents = before.heads().stream().map(ValidatedToken::objectId).toList();
            var plan = TokenPublicationPlan.planAssertion(TokenPublicationTest.tokenId(), explicitParents,
                    TokenPublicationTest.value(1, "Z"), TokenPublicationTest.metadata(), TokenPublicationTest.root());
            publish(directory, plan); checkFiles(directory, plan);
            var observed = read(directory);
            assertTrue(observed.candidateDiagnostics().isEmpty());
            var after = TokenGraph.evaluate(observed.validatedTokens()).perToken(TokenPublicationTest.tokenId());
            var last = plan.stages().get(plan.stages().size() - 1);
            assertEquals(List.of(List.of(new ValidatedToken(last.objectId(), last.token()))), after.currentGroups());
            assertEquals(java.util.Set.of(TokenPublicationTest.value(1, "Z")), after.currentValues());
            assertEquals(width + plan.stages().size(), after.objects().size());
            assertTrue(after.unresolvedParents().isEmpty());
            for (var stage : plan.stages()) assertEquals(TokenPublicationTest.metadata(), stage.token().metadata());
            try (var store = NioV1ObjectPublicationStore.open(directory, path -> fail("Exact retry requested persistence"))) {
                assertEquals(Collections.nCopies(plan.stages().size(), ALREADY_PRESENT_EXACT),
                        TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
            }
            assertEquals(observed, read(directory));
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    @Test void exactExistingIsReadOnlyAndCollisionRemainsUntouched() throws Exception {
        Path directory = directory();
        try {
            var plan = TokenPublicationTest.plan(0); publish(directory, plan);
            var stage = plan.stages().get(0);
            Path target = directory.resolve("objects-v1").resolve(stage.objectId().filename());
            byte[] bytes = Files.readAllBytes(target);
            var attributes = Files.readAttributes(target, BasicFileAttributes.class);
            var permissions = Files.getPosixFilePermissions(target);
            var faults = new ObjectPublicationFaults(path -> fail("Exact target must not be forced"));
            try (var store = faults.open(directory)) {
                assertEquals(List.of(ALREADY_PRESENT_EXACT), TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
            }
            assertEquals(List.of("snapshot", "mkdir", "existing-read"), faults.events);
            var after = Files.readAttributes(target, BasicFileAttributes.class);
            assertEquals(attributes.fileKey(), after.fileKey());
            assertEquals(attributes.lastModifiedTime(), after.lastModifiedTime());
            assertEquals(permissions, Files.getPosixFilePermissions(target));
            assertArrayEquals(bytes, Files.readAllBytes(target));
            byte[] wrong = bytes.clone(); wrong[0] ^= 1; Files.write(target, wrong);
            try (var store = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
                assertThrows(IOException.class, () -> TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
            }
            assertArrayEquals(wrong, Files.readAllBytes(target));
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    @Test void completeStageExistsBeforeExclusiveInstallation() throws Exception {
        Path directory = directory();
        try {
            var plan = TokenPublicationTest.plan(0); var stage = plan.stages().get(0);
            Path namespace = directory.resolve("objects-v1"); Path target = namespace.resolve(stage.objectId().filename());
            var faults = new ObjectPublicationFaults(new NioDurability()); faults.writeLimit = 7;
            faults.action = point -> {
                if (List.of("write", "stage-sync", "before-link").contains(point)) assertFalse(Files.exists(target));
                if (point.equals("before-link")) {
                    assertTrue(faults.events.contains("stage-sync"));
                    try (var entries = Files.list(namespace)) {
                        var names = entries.toList(); assertEquals(1, names.size());
                        assertTrue(names.get(0).getFileName().toString().startsWith(".totipo-object-"));
                        assertEquals(1024, Files.size(names.get(0)));
                    }
                }
                if (point.equals("directory-sync")) assertEquals(1024, Files.size(target));
            };
            try (var store = faults.open(directory)) { TokenPublisher.publish(plan, TokenPublicationTest.root(), store); }
            assertTrue(faults.events.contains("directory-sync")); checkFiles(directory, plan);
        } finally { StorageVectorChecks.deleteTree(directory); }
    }

    @ParameterizedTest @ValueSource(strings = {"before-link", "directory-sync"})
    void realBackendFaultsStopFoldAndAllowExactRetry(String failure) throws Exception {
        Path directory = directory();
        try {
            var plan = TokenPublicationTest.plan(11);
            var faults = new ObjectPublicationFaults(new NioDurability());
            int[] stages = {0};
            faults.action = point -> {
                if (point.equals("snapshot")) stages[0]++;
                if (stages[0] == 3 && point.equals(failure)) throw new IOException("Injected backend failure");
            };
            try (var store = faults.open(directory)) {
                assertThrows(IOException.class, () -> TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
            }
            assertEquals(3, stages[0]);
            assertEquals(failure.equals("before-link") ? 2 : 3, read(directory).validatedTokens().size());
            try (var store = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
                assertEquals(List.of(ALREADY_PRESENT_EXACT, ALREADY_PRESENT_EXACT,
                        failure.equals("before-link") ? PUBLISHED_NEW : ALREADY_PRESENT_EXACT, PUBLISHED_NEW),
                        TokenPublisher.publish(plan, TokenPublicationTest.root(), store));
            }
            checkFiles(directory, plan);
        } finally { StorageVectorChecks.deleteTree(directory); }
    }
}
