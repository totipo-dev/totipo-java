package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.LinuxDurability;

import dev.totipo.platform.linux.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultStorageCrashProcess.*;
import static dev.totipo.format.VaultLifecycleResult.Status.*;
import static dev.totipo.format.VaultBindingStore.State.*;

@Timeout(120)
class LinuxVaultLifecycleIntegrationTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path directory(String name) throws IOException { return Files.createDirectory(dir.resolve(name)); }
    static void phase(VaultBindingStore memory, VaultBindingStore.State expected) throws IOException {
        assertEquals(expected,memory.read().state());
        if (expected == PRESENT) assertArrayEquals(binding(),memory.read().bytes());
    }
    static void failed(VaultLifecycleResult result, VaultLifecycleResult.Status expected) {
        try (result) { assertEquals(expected, result.status()); assertNull(result.root()); assertNull(result.discovery()); }
    }
    static final class ObservedDiscovery implements DiscoverySource {
        final NioDiscoverySource real; final VaultBindingStore memory;
        int snapshots, reads;
        ObservedDiscovery(Path root, VaultBindingStore memory) { real = new NioDiscoverySource(root); this.memory = memory; }
        @Override public Snapshot snapshot() throws IOException {
            snapshots++; var snapshot = real.snapshot();
            return new Snapshot(snapshot.candidates().stream().map(c -> new Candidate(c.id(), () -> {
                assertEquals(PRESENT, memory.read().state()); reads++; return c.opener().open();
            })).toList(), snapshot.issue(), snapshot);
        }
    }
    @Test void cleanRealCreationOrderingDiscoveryAndSubsequentReopen() throws Exception {
        Path sync = directory("sync"), local = directory("local"); var faults = new VaultStorageFaults(LinuxDurability.open());
        try (var memory = LinuxVaultBindingStore.open(local); var vault = faults.open(sync)) {
            faults.beforeStage = () -> { phase(memory, ABSENT); assertFalse(Files.exists(sync.resolve("vault"))); };
            faults.beforeLink = () -> { phase(memory, ABSENT); assertFalse(Files.exists(sync.resolve("vault"))); };
            // A candidate arrives after empty preflight. Classification must wait for durable ESTABLISHED.
            faults.afterDirectory = () -> Files.write(Files.createDirectory(sync.resolve("objects-v1")).resolve("a".repeat(64)), new byte[]{1});
            var source = new ObservedDiscovery(sync, memory);
            try (var result = lifecycle(vault, memory, source).createNew(PASSWORD)) {
                assertEquals(CREATED_ESTABLISHED, result.status()); assertArrayEquals(ROOT, result.root());
                assertEquals(DiscoveryState.READY, result.discovery().discoveryState());
                assertTrue(result.discovery().resourceComplete());
            }
            phase(memory, PRESENT); assertEquals(2, source.snapshots); assertEquals(1, source.reads);
            assertEquals(87, Files.size(sync.resolve("vault"))); assertArrayEquals(candidate(), Files.readAllBytes(sync.resolve("vault")));
        }
        try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
            var source = new ObservedDiscovery(sync, memory);
            try (var result = lifecycle(vault, memory, source).openConfigured(PASSWORD)) {
                assertEquals(OPENED_ESTABLISHED, result.status()); assertArrayEquals(ROOT, result.root());
            }
            phase(memory, PRESENT); assertEquals(1, source.snapshots); assertEquals(1, source.reads);
        }
    }
    @Test void establishedWrongPasswordDifferentRootAndAbsentNeverDiscoverOrRewriteLocal() throws Exception {
        Path sync = directory("sync"), local = directory("local");
        try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
            try (var result = lifecycle(vault, memory, new NioDiscoverySource(sync)).createNew(PASSWORD)) {
                assertEquals(CREATED_ESTABLISHED, result.status());
            }
        }
        byte[] before = Files.readAllBytes(local.resolve("vault-binding-v1.bin"));
        try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
            var source = new ObservedDiscovery(sync, memory); var lifecycle = lifecycle(vault, memory, source);
            failed(lifecycle.openConfigured(CryptoSupport.ascii("wrong")), AUTHENTICATION_FAILED);
            byte[] other = ROOT.clone(); other[0] ^= 1;
            Files.write(sync.resolve("vault"), new VaultBootstrapWriter().encode(PASSWORD, other, field(16), field(12)));
            failed(lifecycle.openConfigured(PASSWORD), ESTABLISHED_BINDING_MISMATCH);
            Files.delete(sync.resolve("vault")); failed(lifecycle.openConfigured(PASSWORD), CANONICAL_VAULT_ABSENT);
            assertEquals(0, source.snapshots); phase(memory, PRESENT);
        }
        assertArrayEquals(before, Files.readAllBytes(local.resolve("vault-binding-v1.bin")));
    }
    @Test void realExistingCandidatesAndIncompletePreflightStopBeforeEntropyOrPending() throws Exception {
        for (boolean incomplete : new boolean[]{false, true}) {
            Path sync = directory("sync" + incomplete), local = directory("local" + incomplete);
            if (incomplete) Files.createSymbolicLink(sync.resolve("objects-v1"), local);
            else Files.write(Files.createDirectory(sync.resolve("objects-v1")).resolve("a".repeat(64)), new byte[]{1});
            var faults = new VaultStorageFaults(LinuxDurability.open());
            try (var memory = LinuxVaultBindingStore.open(local); var vault = faults.open(sync)) {
                var source = new ObservedDiscovery(sync, memory);
                var lifecycle = new VaultLifecycle(vault, memory, source, b -> { throw new AssertionError("entropy before preflight"); },
                        new VaultBootstrapWriter(), new VaultUnlocker());
                failed(lifecycle.createNew(PASSWORD), incomplete ? CREATE_BLOCKED_DISCOVERY_INCOMPLETE : CREATE_BLOCKED_EXISTING_OBJECT_CANDIDATES);
                assertEquals(ABSENT, memory.read().state()); assertEquals(0, source.reads);
                assertTrue(faults.events.isEmpty()); assertFalse(Files.exists(sync.resolve("vault")));
            }
        }
    }
    @Test void realFaultMatrixRetainsPendingAndRecoversActualCanonical() throws Exception {
        for (String failure : List.of("write", "stage-sync", "link", "directory-sync", "temporary")) {
            Path sync = directory("sync-" + failure), local = directory("local-" + failure);
            var faults = new VaultStorageFaults(LinuxDurability.open()); faults.fail = failure;
            try (var memory = LinuxVaultBindingStore.open(local); var vault = faults.open(sync)) {
                var source = new ObservedDiscovery(sync, memory);
                failed(lifecycle(vault, memory, source).createNew(PASSWORD), PUBLICATION_INCOMPLETE);
                phase(memory, ABSENT); assertEquals(1, source.snapshots); assertEquals(0, source.reads);
            }
            boolean linked = failure.equals("directory-sync");
            try (var names = Files.list(sync)) { assertEquals(linked ? List.of("vault") : List.of(), names.map(p -> p.getFileName().toString()).toList()); }
            try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
                phase(memory, ABSENT); var source = new ObservedDiscovery(sync, memory);
                try (var result = lifecycle(vault, memory, source).openConfigured(PASSWORD)) {
                    assertEquals(linked ? OPENED_ESTABLISHED : CANONICAL_VAULT_ABSENT, result.status());
                }
                phase(memory, linked ? PRESENT : ABSENT); assertEquals(linked ? 1 : 0, source.snapshots);
            }
        }
    }
    @Test void collisionDoesNotAdoptCanonicalInSameCreateCall() throws Exception {
        Path sync = directory("sync"), local = directory("local"); var faults = new VaultStorageFaults(LinuxDurability.open());
        byte[] existing = candidate(); faults.beforeLink = () -> Files.write(sync.resolve("vault"), existing);
        try (var memory = LinuxVaultBindingStore.open(local); var backend = faults.open(sync)) {
            int[] reads = {0};
            var vault = new Forwarding(backend) {
                @Override public InputStream openCanonicalRead() throws IOException { reads[0]++; return super.openCanonicalRead(); }
            };
            failed(lifecycle(vault, memory, new NioDiscoverySource(sync)).createNew(PASSWORD), PUBLICATION_INCOMPLETE);
            assertEquals(1, reads[0]); phase(memory, ABSENT); assertArrayEquals(existing, Files.readAllBytes(sync.resolve("vault")));
        }
        try (var entries = Files.list(sync)) { assertEquals(1, entries.count()); }
    }
    @Test void substitutionAfterSuccessfulInstallIsRejectedByCore() throws Exception {
        Path sync = directory("sync"), local = directory("local"); var faults = new VaultStorageFaults(LinuxDurability.open());
        byte[] otherRoot = ROOT.clone(); otherRoot[2] ^= 1;
        byte[] other = new VaultBootstrapWriter().encode(PASSWORD, otherRoot, field(16), field(12));
        boolean[] installed = {false};
        faults.afterDirectory = () -> {
            installed[0] = true;
            Files.delete(sync.resolve("vault")); Files.write(sync.resolve("vault"), other);
        };
        try (var memory = LinuxVaultBindingStore.open(local); var vault = faults.open(sync)) {
            var source = new ObservedDiscovery(sync, memory);
            failed(lifecycle(vault, memory, source).createNew(PASSWORD), PUBLICATION_INCOMPLETE);
            assertTrue(installed[0]); phase(memory, ABSENT); assertEquals(1, source.snapshots);
            try (var opened = lifecycle(vault, memory, source).openConfigured(PASSWORD)) { assertEquals(OPENED_ESTABLISHED,opened.status()); }
            assertEquals(2, source.snapshots);
        }
    }
    static class Forwarding implements VaultBootstrapStorage {
        final VaultBootstrapStorage delegate;
        Forwarding(VaultBootstrapStorage delegate) { this.delegate = delegate; }
        @Override public InputStream openCanonicalRead() throws IOException { return delegate.openCanonicalRead(); }
        @Override public StagedBootstrap stageInitial(byte[] bytes) throws IOException { return delegate.stageInitial(bytes); }
        @Override public void close() throws IOException { delegate.close(); }
    }
    @Test void hugeCanonicalReadIsBoundedByCoreAt88Bytes() throws Exception {
        Path sync = directory("sync"), local = directory("local");
        try (var file = FileChannel.open(sync.resolve("vault"), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            file.write(ByteBuffer.wrap(candidate())); file.write(ByteBuffer.wrap(new byte[]{1}), 1L << 30);
        }
        try (var memory = LinuxVaultBindingStore.open(local); var backend = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {

            int[] consumed = {0};
            var vault = new Forwarding(backend) {
                @Override public InputStream openCanonicalRead() throws IOException {
                    return new FilterInputStream(super.openCanonicalRead()) {
                        @Override public int read(byte[] b, int offset, int length) throws IOException {
                            assertTrue(length <= 88); int n = super.read(b, offset, Math.min(length, 7));
                            if (n > 0) consumed[0] += n; return n;
                        }
                    };
                }
            };
            var source = new ObservedDiscovery(sync, memory);
            failed(lifecycle(vault, memory, source).openConfigured(PASSWORD), INVALID_BOOTSTRAP);
            assertEquals(88, consumed[0]); assertEquals(0, source.snapshots); phase(memory, ABSENT);
        }
    }
    Process child(String mode, Path sync, Path local) throws Exception {
        var paths = new ArrayList<String>();
        for (Class<?> type : List.of(VaultStorageFaults.class, LinuxDurability.class, VaultStorageCrashProcess.class, NioVaultBootstrapStorage.class,
                VaultBootstrapStorage.class, Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator")))
            paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED", "--illegal-native-access=deny", "-cp", String.join(File.pathSeparator, paths),
                VaultStorageCrashProcess.class.getName(), mode, sync.toString(), local.toString()).redirectErrorStream(true).start();
    }
    void halt(String mode, Path sync, Path local) throws Exception {
        var process = child(mode, sync, local);
        try {
            assertTrue(process.waitFor(60, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue(), new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        } finally { process.destroyForcibly(); }
    }
    @Test void stageOnlyHaltLeavesPendingAbsentWithoutNamedResidue() throws Exception {
        Path sync = directory("sync"), local = directory("local"); halt("stage", sync, local);
        try (var entries = Files.list(sync)) { assertTrue(entries.allMatch(p -> p.getFileName().toString().startsWith(".totipo-vault-"))); }
        try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
            phase(memory, ABSENT); var source = new ObservedDiscovery(sync, memory);
            failed(lifecycle(vault, memory, source).openConfigured(PASSWORD), CANONICAL_VAULT_ABSENT);
            phase(memory, ABSENT); assertEquals(0, source.snapshots);
        }
    }
    @Test void successfulInstallThenHaltNeedsNoJavaCloseForCanonicalAuthentication() throws Exception {
        Path sync = directory("sync"), local = directory("local"); halt("install", sync, local);
        assertEquals(87, Files.size(sync.resolve("vault")));
        try (var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open());
             var unlocked = new VaultUnlocker().unlock(VaultLifecycle.read(vault.openCanonicalRead()), PASSWORD)) {
            assertEquals(VaultUnlockResult.Status.UNLOCKED, unlocked.status()); assertArrayEquals(ROOT, unlocked.root());
        }
    }
    @Test void fullLifecycleHaltAndPublicationBeforeEstablishmentHaltRecover() throws Exception {
        for (String mode : List.of("full", "pending-published")) {
            Path sync = directory("sync-" + mode), local = directory("local-" + mode); halt(mode, sync, local);
            try (var memory = LinuxVaultBindingStore.open(local); var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open())) {
                phase(memory, mode.equals("full") ? PRESENT : ABSENT);
                var source = new ObservedDiscovery(sync, memory);
                try (var result = lifecycle(vault, memory, source).openConfigured(PASSWORD)) {
                    assertEquals(OPENED_ESTABLISHED, result.status()); assertArrayEquals(ROOT, result.root());
                    assertTrue(result.discovery().resourceComplete());
                }
                phase(memory, PRESENT); assertEquals(1, source.snapshots);
            }
        }
    }
    @Test void separateProcessesRaceOnlyOneInitialLinkSucceeds() throws Exception {
        Path sync = directory("sync"), local = directory("local");
        var first = child("contend", sync, local); var second = child("contend", sync, local);
        try (var executor = Executors.newFixedThreadPool(2)) {
            try {
                for (var process : List.of(first, second)) {
                    var ready = executor.submit(() -> new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine());
                    assertEquals("READY", ready.get(30, TimeUnit.SECONDS));
                }
                for (var process : List.of(first, second)) { process.getOutputStream().write('G'); process.getOutputStream().flush(); }
                assertTrue(first.waitFor(30, TimeUnit.SECONDS)); assertTrue(second.waitFor(30, TimeUnit.SECONDS));
                assertEquals(Set.of(0, 3), Set.of(first.exitValue(), second.exitValue()));
                assertArrayEquals(candidate(), Files.readAllBytes(sync.resolve("vault")));
            } finally { first.destroyForcibly(); second.destroyForcibly(); }
        }
    }
    @Test void independentRealLifecycleCreatorsLeaveWinnerEstablishedAndLoserPending() throws Exception {
        Path sync = directory("sync"); var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var results = new ArrayList<Future<VaultLifecycleResult.Status>>();
            for (int i = 0; i < 2; i++) {
                Path local = directory("local" + i); final byte rootByte = (byte) (37 + i);
                results.add(executor.submit(() -> {
                    var faults = new VaultStorageFaults(LinuxDurability.open());
                    faults.beforeLink = () -> {
                        try { barrier.await(30, TimeUnit.SECONDS); }
                        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IOException(e); }
                        catch (BrokenBarrierException | TimeoutException e) { throw new IOException(e); }
                    };
                    try (var memory = LinuxVaultBindingStore.open(local); var vault = faults.open(sync)) {
                        var lifecycle = new VaultLifecycle(vault, memory, new NioDiscoverySource(sync),
                                bytes -> Arrays.fill(bytes, rootByte), new VaultBootstrapWriter(), new VaultUnlocker());
                        try (var result = lifecycle.createNew(PASSWORD)) {
                            assertEquals(result.status() == CREATED_ESTABLISHED ? PRESENT : ABSENT,
                                    memory.read().state());
                            return result.status();
                        }
                    }
                }));
            }
            var statuses = results.stream().map(future -> {
                try { return future.get(); } catch (Exception e) { throw new AssertionError(e); }
            }).toList();
            assertEquals(Set.of(CREATED_ESTABLISHED, PUBLICATION_INCOMPLETE), new HashSet<>(statuses));
            try (var memory = LinuxVaultBindingStore.open(dir.resolve("local" + statuses.indexOf(CREATED_ESTABLISHED)));
                 var vault = NioVaultBootstrapStorage.open(sync, LinuxDurability.open());
                 var result = lifecycle(vault, memory, new NioDiscoverySource(sync)).openConfigured(PASSWORD)) {
                assertEquals(OPENED_ESTABLISHED, result.status());
            }
        }
    }
}
