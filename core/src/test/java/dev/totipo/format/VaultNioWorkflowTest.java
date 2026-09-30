package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultLifecycle.PasswordChangeResult.*;
import static dev.totipo.format.VaultUnlockResult.Status.*;
import static dev.totipo.format.VaultLifecycleTest.filled;

import dev.totipo.storage.nio.NioDiscoverySource;
import dev.totipo.storage.nio.NioDurability;
import dev.totipo.storage.nio.NioV1ObjectPublicationStore;
import dev.totipo.storage.nio.NioVaultBootstrapStorage;
import dev.totipo.storage.nio.VaultStorageFaults;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Real Argon2id, real NIO, and accepted local force operations; not physical power-loss proof. */
class VaultNioWorkflowTest {
    @TempDir Path directory;
    private static final byte[] A = CryptoSupport.ascii("password A"), B = CryptoSupport.ascii("password B");
    private static VaultLifecycle lifecycle(int seed) {
        int[] draws = {seed};
        return new VaultLifecycle(new VaultBootstrapWriter(), new VaultUnlocker(),
                bytes -> Arrays.fill(bytes, (byte) ++draws[0]));
    }
    private NioVaultBootstrapStorage storage() throws IOException { return NioVaultBootstrapStorage.open(directory, new NioDurability()); }
    private byte[] create() throws IOException {
        try (var storage = storage(); var result = lifecycle(10).createNew(storage, A)) {
            assertEquals(VaultLifecycle.CreationStatus.CREATED, result.status()); return result.root();
        }
    }
    private static Map<String, String> objects(Path directory) throws IOException {
        var result = new TreeMap<String, String>();
        try (var entries = Files.list(directory.resolve("objects-v1"))) {
            for (var entry : entries.toList()) result.put(entry.getFileName().toString(),
                    java.util.HexFormat.of().formatHex(Files.readAllBytes(entry)));
        }
        return result;
    }

    @Test void emptyRootCreateCloseReopenUsesOnlyCanonicalAndExactGeneratedRoot() throws Exception {
        var faults = new VaultStorageFaults(new NioDurability()); faults.writeLimit = 3;
        faults.beforeWrite = () -> assertFalse(Files.exists(directory.resolve("vault")));
        faults.afterStageSync = () -> assertFalse(Files.exists(directory.resolve("vault")));
        faults.beforeLink = () -> {
            assertFalse(Files.exists(directory.resolve("vault")));
            try (var entries = Files.list(directory)) {
                var paths = entries.toList(); assertEquals(1, paths.size()); assertEquals(87, Files.size(paths.get(0)));
            }
        };
        try (var store = faults.open(directory); var result = lifecycle(10).createNew(store, A)) {
            assertEquals(VaultLifecycle.CreationStatus.CREATED, result.status());
            assertArrayEquals(filled(32, 11), result.root());
            assertArrayEquals(CryptoSupport.vaultFingerprint(filled(32, 11)), result.fingerprint());
        }
        assertEquals(87, Files.size(directory.resolve("vault")));
        assertFalse(Files.exists(directory.resolve("objects-v1")));
        try (var store = storage(); var opened = lifecycle(20).open(store, A)) {
            assertEquals(UNLOCKED, opened.status()); assertArrayEquals(filled(32, 11), opened.root());
        }
        assertTrue(faults.events.indexOf("stage-sync") < faults.events.indexOf("link"));
        assertTrue(faults.events.contains("directory-sync"));
    }

    @Test void orphanObjectsAndBootstrapLookalikesNeverGateOrChangeCanonicalWorkflows() throws Exception {
        Path namespace = Files.createDirectory(directory.resolve("objects-v1"));
        Files.write(namespace.resolve("a".repeat(64)), filled(1024, 93));
        Files.write(namespace.resolve("orphan.tmp"), new byte[]{4, 5});
        var originalObjects = objects(directory);
        var siblings = List.of("VAULT", "vault.tmp", "vault.bak", "vault.sync-conflict", "vault (conflicted copy)");
        byte[] alternate = new VaultBootstrapWriter().encode(B, filled(32, 99), filled(16, 98), filled(12, 97));
        for (var sibling : siblings) Files.write(directory.resolve(sibling), alternate);
        try (var store = storage(); var opened = lifecycle(0).open(store, B)) { assertEquals(ABSENT, opened.status()); }
        byte[] root = create();
        try (var store = storage(); var opened = lifecycle(0).open(store, A)) {
            assertArrayEquals(root, opened.root()); assertEquals(SUCCESS, lifecycle(20).changePassword(store, A, B));
        }
        try (var store = storage(); var opened = lifecycle(0).open(store, B)) { assertArrayEquals(root, opened.root()); }
        assertEquals(originalObjects, objects(directory));
        for (var sibling : siblings) assertArrayEquals(alternate, Files.readAllBytes(directory.resolve(sibling)));
    }

    @Test void rewrapPreservesRootFingerprintAndHistoricalWrapperStillWorks() throws Exception {
        byte[] root = create(); byte[] base = Files.readAllBytes(directory.resolve("vault"));
        byte[] fingerprint = CryptoSupport.vaultFingerprint(root);
        var faults = new VaultStorageFaults(new NioDurability()); faults.writeLimit = 3;
        faults.beforeWrite = () -> assertArrayEquals(base, Files.readAllBytes(directory.resolve("vault")));
        try (var store = faults.open(directory)) { assertEquals(SUCCESS, lifecycle(20).changePassword(store, A, B)); }
        assertFalse(Arrays.equals(base, Files.readAllBytes(directory.resolve("vault"))));
        try (var store = storage(); var opened = lifecycle(0).open(store, B); var old = lifecycle(0).open(store, A);
             var historical = new VaultUnlocker().unlock(base, A)) {
            assertEquals(UNLOCKED, opened.status()); assertArrayEquals(root, opened.root());
            assertArrayEquals(fingerprint, opened.fingerprint()); assertEquals(AUTHENTICATION_FAILED, old.status());
            assertEquals(UNLOCKED, historical.status()); assertArrayEquals(root, historical.root());
            assertArrayEquals(fingerprint, historical.fingerprint());
        }
    }

    @ParameterizedTest @ValueSource(strings = {"existing", "race", "directory", "symlink", "fifo"})
    void noReplaceCreationNeverOverwritesExistingOrRacingEntry(String kind) throws Exception {
        Path canonical = directory.resolve("vault"); byte[] existing = {42, 13};
        Path destination = directory.resolve("destination"); Files.write(destination, existing);
        var faults = new VaultStorageFaults(new NioDurability());
        switch (kind) {
            case "existing" -> Files.write(canonical, existing);
            case "race" -> faults.beforeLink = () -> Files.write(canonical, existing);
            case "directory" -> Files.createDirectory(canonical);
            case "symlink" -> Files.createSymbolicLink(canonical, destination);
            case "fifo" -> assertEquals(0, new ProcessBuilder("mkfifo", canonical.toString()).start().waitFor());
            default -> fail();
        }
        try (var store = faults.open(directory); var result = lifecycle(10).createNew(store, A)) {
            assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status());
            try (var opened = lifecycle(0).open(store, A)) {
                assertEquals(List.of("existing", "race").contains(kind) ? INVALID_FORMAT : UNAVAILABLE, opened.status());
            }
        }
        assertTrue(Files.exists(canonical, LinkOption.NOFOLLOW_LINKS));
        if (List.of("existing", "race").contains(kind)) assertArrayEquals(existing, Files.readAllBytes(canonical));
        if (kind.equals("symlink")) assertTrue(Files.isSymbolicLink(canonical));
        if (kind.equals("directory")) assertTrue(Files.isDirectory(canonical, LinkOption.NOFOLLOW_LINKS));
        if (kind.equals("fifo")) assertFalse(Files.isRegularFile(canonical, LinkOption.NOFOLLOW_LINKS));
        assertArrayEquals(existing, Files.readAllBytes(destination));
        assertEquals(kind.equals("race") ? 1 : 0, faults.stageSyncs);
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void deterministicConcurrentReplacementIsStaleForSameOrDifferentRoot(boolean differentRoot) throws Exception {
        byte[] originalRoot = create(); byte[][] intervening = {null};
        var faults = new VaultStorageFaults(new NioDurability());
        faults.afterStageSync = () -> {
            // Operation 1 has authenticated BASE and staged; operation 2 now completes.
            try (var second = storage()) {
                if (differentRoot) {
                    byte[] other = new VaultBootstrapWriter().encode(B, filled(32, 99), filled(16, 98), filled(12, 97));
                    try (var stage = second.stageReplacement(other)) { stage.replaceCanonicalDurably(); }
                } else assertEquals(SUCCESS, lifecycle(30).changePassword(second, A, B));
            }
            intervening[0] = Files.readAllBytes(directory.resolve("vault"));
        };
        try (var first = faults.open(directory)) {
            assertEquals(STALE, lifecycle(20).changePassword(first, A, CryptoSupport.ascii("losing password")));
        }
        assertFalse(faults.events.contains("move")); assertArrayEquals(intervening[0], Files.readAllBytes(directory.resolve("vault")));
        try (var store = storage(); var opened = lifecycle(0).open(store, B)) {
            assertArrayEquals(differentRoot ? filled(32, 99) : originalRoot, opened.root());
            assertEquals(!differentRoot, Arrays.equals(CryptoSupport.vaultFingerprint(originalRoot), opened.fingerprint()));
        }
    }

    @ParameterizedTest @ValueSource(strings = {"directory", "symlink", "absent", "malformed"})
    void changedOrUnsafeCurrentIsNeverReplaced(String kind) throws Exception {
        create(); Path canonical = directory.resolve("vault");
        Path saved = directory.resolve("saved"); Files.copy(canonical, saved);
        var faults = new VaultStorageFaults(new NioDurability());
        faults.afterStageSync = () -> {
            Files.delete(canonical);
            switch (kind) {
                case "directory" -> Files.createDirectory(canonical);
                case "symlink" -> Files.createSymbolicLink(canonical, saved);
                case "malformed" -> Files.write(canonical, new byte[]{1, 2});
                case "absent" -> { }
                default -> fail();
            }
        };
        try (var store = faults.open(directory)) {
            assertEquals(kind.equals("malformed") ? STALE : FAILED, lifecycle(20).changePassword(store, A, B));
        }
        assertFalse(faults.events.contains("move"));
        if (kind.equals("malformed")) assertArrayEquals(new byte[]{1, 2}, Files.readAllBytes(canonical));
        if (kind.equals("directory")) assertTrue(Files.isDirectory(canonical));
        if (kind.equals("symlink")) assertTrue(Files.isSymbolicLink(canonical));
        if (kind.equals("absent")) assertFalse(Files.exists(canonical));
    }

    @ParameterizedTest @ValueSource(strings = {"link", "move", "directory-sync", "unsupported-move", "unsupported-directory"})
    void backendFailuresAreHonestAndNoAutomaticRetryOrRollbackOccurs(String failure) throws Exception {
        boolean replacing = failure.equals("move") || failure.equals("unsupported-move");
        byte[] old = null;
        if (replacing) { create(); old = Files.readAllBytes(directory.resolve("vault")); }
        var faults = new VaultStorageFaults(failure.equals("unsupported-directory")
                ? path -> { throw new IOException("Injected unsupported directory force"); } : new NioDurability());
        faults.fail = failure; faults.unsupportedMove = failure.equals("unsupported-move");
        try (var store = faults.open(directory)) {
            if (replacing) assertEquals(FAILED, lifecycle(20).changePassword(store, A, B));
            else try (var result = lifecycle(10).createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        }
        if (replacing) assertArrayEquals(old, Files.readAllBytes(directory.resolve("vault")));
        else assertEquals(!failure.equals("link"), Files.exists(directory.resolve("vault")));
        assertEquals(1, faults.events.stream().filter(e -> e.equals(replacing ? "move" : "link")).count());
        if (!failure.equals("link")) try (var store = storage(); var opened = lifecycle(0).open(store, A)) { assertEquals(UNLOCKED, opened.status()); }
    }

    @Test void replacementDirectoryFailureMayLeaveNewWrapperButMustReturnFailed() throws Exception {
        byte[] root = create(); var faults = new VaultStorageFaults(new NioDurability()); faults.fail = "directory-sync";
        try (var store = faults.open(directory)) { assertEquals(FAILED, lifecycle(20).changePassword(store, A, B)); }
        assertEquals(1, faults.events.stream().filter("move"::equals).count());
        try (var store = storage(); var opened = lifecycle(0).open(store, B)) { assertArrayEquals(root, opened.root()); }
    }

    @Test void createOpenPublishReopenGraphRewrapReopenLeavesTokensExactlyUnchanged() throws Exception {
        create(); TokenPublicationPlan plan;
        try (var store = storage(); var opened = lifecycle(0).open(store, A);
             var objects = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
            byte[] root = opened.root();
            try {
                plan = TokenPublicationPlan.planNew(TokenPublicationTest.value(1, "account"), TokenPublicationTest.metadata(),
                        bytes -> Arrays.fill(bytes, (byte) 42), root);
                assertEquals(List.of(V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW), TokenPublisher.publish(plan, root, objects));
            } finally { Arrays.fill(root, (byte) 0); }
        }
        var originalObjects = objects(directory); TokenStoreObservation before;
        try (var store = storage(); var opened = lifecycle(0).open(store, A)) {
            byte[] root = opened.root();
            try { before = TokenStoreReader.read(new NioDiscoverySource(directory), root); }
            finally { Arrays.fill(root, (byte) 0); }
        }
        var stage = plan.stages().get(0); var token = stage.token();
        assertEquals(new TokenId(filled(32, 42)), token.tokenId());
        assertEquals(TokenPublicationTest.value(1, "account"), token.value());
        assertEquals(TokenPublicationTest.metadata(), token.metadata());
        assertEquals(List.of(new ValidatedToken(stage.objectId(), token)), before.validatedTokens());
        var graph = TokenGraph.evaluate(before.validatedTokens()).perToken(token.tokenId());
        assertEquals(before.validatedTokens(), graph.heads());
        try (var store = storage()) { assertEquals(SUCCESS, lifecycle(20).changePassword(store, A, B)); }
        assertEquals(originalObjects, objects(directory));
        try (var store = storage(); var opened = lifecycle(0).open(store, B)) {
            byte[] root = opened.root();
            try {
                var after = TokenStoreReader.read(new NioDiscoverySource(directory), root);
                assertEquals(before, after);
                assertEquals(graph, TokenGraph.evaluate(after.validatedTokens()).perToken(token.tokenId()));
            } finally { Arrays.fill(root, (byte) 0); }
        }
    }

    @Test void independentVaultsHaveDifferentFingerprintsAndCannotAuthenticateEachOthersObjects() throws Exception {
        byte[] rootA = create(); Path other = Files.createDirectory(directory.resolve("other"));
        try (var otherStore = NioVaultBootstrapStorage.open(other, new NioDurability()); var created = lifecycle(60).createNew(otherStore, A)) {
            assertEquals(VaultLifecycle.CreationStatus.CREATED, created.status());
            assertFalse(Arrays.equals(CryptoSupport.vaultFingerprint(rootA), created.fingerprint()));
            var plan = TokenPublicationPlan.planNew(TokenPublicationTest.value(1, "account"), TokenPublicationTest.metadata(), rootA);
            try (var objects = NioV1ObjectPublicationStore.open(directory, new NioDurability())) { TokenPublisher.publish(plan, rootA, objects); }
            byte[] rootB = created.root();
            try {
                var observation = TokenStoreReader.read(new NioDiscoverySource(directory), rootB);
                assertTrue(observation.validatedTokens().isEmpty()); assertEquals(1, observation.candidateDiagnostics().size());
            } finally { Arrays.fill(rootB, (byte) 0); Arrays.fill(rootA, (byte) 0); }
        }
    }

    @Test void unusableTokenNamespaceIsNotAVaultOperationGate() throws Exception {
        Path namespace = directory.resolve("objects-v1"); byte[] unrelated = {1, 2, 3};
        Files.write(namespace, unrelated);
        byte[] root = create();
        try (var store = storage(); var opened = lifecycle(0).open(store, A)) {
            assertArrayEquals(root, opened.root()); assertEquals(SUCCESS, lifecycle(20).changePassword(store, A, B));
        }
        assertArrayEquals(unrelated, Files.readAllBytes(namespace));
    }

    @Test void conflictingTokensAndMissingParentsDoNotGateRewrapOrChangeGraph() throws Exception {
        byte[] root = create();
        try (var objects = NioV1ObjectPublicationStore.open(directory, new NioDurability())) {
            for (String value : List.of("one", "two")) {
                var plan = TokenPublicationPlan.planAssertion(TokenPublicationTest.tokenId(), TokenPublicationTest.parents(1),
                        TokenPublicationTest.value(1, value), TokenPublicationTest.metadata(), root);
                TokenPublisher.publish(plan, root, objects);
            }
        }
        var before = TokenStoreReader.read(new NioDiscoverySource(directory), root);
        var view = TokenGraph.evaluate(before.validatedTokens()).perToken(TokenPublicationTest.tokenId());
        assertEquals(2, view.currentGroups().size()); assertFalse(view.unresolvedParents().isEmpty());
        var bytes = objects(directory);
        try (var store = storage()) { assertEquals(SUCCESS, lifecycle(20).changePassword(store, A, B)); }
        assertEquals(bytes, objects(directory));
        assertEquals(before, TokenStoreReader.read(new NioDiscoverySource(directory), root));
        Arrays.fill(root, (byte) 0);
    }

    @Test void corruptCompletedNioStageIsRejectedBeforeInstall() throws Exception {
        var faults = new VaultStorageFaults(new NioDurability());
        faults.afterStageSync = () -> {
            try (var entries = Files.list(directory)) {
                Path stage = entries.findFirst().orElseThrow();
                byte[] bytes = Files.readAllBytes(stage); bytes[86] ^= 1; Files.write(stage, bytes);
            }
        };
        try (var store = faults.open(directory); var result = lifecycle(10).createNew(store, A)) {
            assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status());
        }
        assertFalse(Files.exists(directory.resolve("vault"))); assertFalse(faults.events.contains("link"));
    }

    @ParameterizedTest @ValueSource(ints = {0, 86, 88, 1000000})
    void nioCanonicalReadsStopAt88BytesAndNeverInvokeKdfForWrongLength(int length) throws Exception {
        Files.write(directory.resolve("vault"), new byte[length]);
        try (var store = storage()) {
            try (var in = store.openCanonicalRead()) { assertEquals(Math.min(length, 88), in.readAllBytes().length); }
            var lifecycle = new VaultLifecycle(new VaultBootstrapWriter(),
                    new VaultUnlocker((p, s) -> { fail("Wrong length reached KDF"); return null; }), bytes -> fail());
            try (var opened = lifecycle.open(store, A)) { assertEquals(INVALID_FORMAT, opened.status()); }
        }
    }
}
