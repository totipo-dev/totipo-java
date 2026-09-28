package dev.totipo.fs.linux;

import dev.totipo.format.VaultBootstrapStorage;
import dev.totipo.format.VaultBootstrapReplacementStorage;
import java.io.IOException;
import java.lang.foreign.FunctionDescriptor;
import java.nio.ByteBuffer;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.io.TempDir;
import static java.lang.foreign.ValueLayout.*;
import static org.junit.jupiter.api.Assertions.*;

@Timeout(60)
class LinuxVaultReplacementTest {
    @TempDir(factory = LocalStorageTempDirectory.class) Path root;
    static byte[] bytes(int seed) { byte[] b = new byte[87]; new Random(seed).nextBytes(b); return b; }
    Path canonical() { return root.resolve("vault"); }
    List<Path> residue() throws IOException {
        try (var paths = Files.list(root)) {
            return paths.filter(p -> p.getFileName().toString().startsWith(LinuxVaultBootstrapStorage.REPLACEMENT_PREFIX)).toList();
        }
    }
    LinuxStatx identity(Path path) throws IOException {
        var libc = new LinuxLibc();
        try (var pin = libc.open(path.toString(), LinuxAbi.PIN)) { return libc.stat(pin); }
    }
    @Test void unnamedSnapshotDistinctCapabilitiesExactIdentityModeAndBarrierOrder() throws Exception {
        byte[] old = bytes(1), candidate = bytes(2), caller = candidate.clone();
        Files.write(canonical(), old);
        Files.setPosixFilePermissions(canonical(), PosixFilePermissions.fromString("rw-r--r--"));
        var oldId = identity(canonical()); var faults = new ReplacementStorageFaults();
        try (var storage = faults.open(root); var stage = storage.stageReplacement(caller)) {
            assertFalse(stage instanceof VaultBootstrapStorage.StagedBootstrap);
            Arrays.fill(caller, (byte) 0);
            assertTrue(residue().isEmpty()); assertArrayEquals(old, Files.readAllBytes(canonical()));
            for (int i = 0; i < 2; i++) try (var read = stage.openRead()) { assertArrayEquals(candidate, read.readAllBytes()); }
            faults.beforeExchange = () -> assertArrayEquals(old, Files.readAllBytes(canonical()));
            stage.replaceCanonicalDurably();
            assertEquals(List.of("stage-sync", "private-link", "exchange", "post-exchange-sync", "unlink", "directory-sync"), faults.events);
            assertEquals(faults.stageIdentity, identity(canonical())); assertNotEquals(oldId, identity(canonical()));
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(canonical()));
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
            assertArrayEquals(candidate, Files.readAllBytes(canonical())); assertEquals(87, Files.size(canonical()));
        }
        assertTrue(residue().isEmpty());
    }
    @Test void replacementSharesCompleteWriteAndCopyWipeOnSuccessAndFailure() throws Exception {
        for (String failure : List.of("none", "write", "sync")) {
            var ops = new LinuxVaultBootstrapStorage.Operations() {
                ByteBuffer observed;
                @Override int write(LinuxLibc libc, LinuxFd fd, ByteBuffer src) throws IOException {
                    if (observed == null) observed = src.duplicate();
                    if (failure.equals("write")) throw new IOException("write");
                    int limit = src.limit(); src.limit(Math.min(limit, src.position() + 7));
                    try { return super.write(libc, fd, src); } finally { src.limit(limit); }
                }
                @Override void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException {
                    if (failure.equals("sync")) throw new IOException("sync"); super.syncStage(libc, fd);
                }
            };
            byte[] caller = bytes(2);
            try (var storage = LinuxVaultBootstrapStorage.open(root, ops)) {
                if (failure.equals("none")) try (var stage = storage.stageReplacement(caller); var read = stage.openRead()) {
                    Arrays.fill(caller, (byte) 0); assertArrayEquals(bytes(2), read.readAllBytes());
                } else assertThrows(IOException.class, () -> storage.stageReplacement(caller));
                byte[] retained = new byte[87]; ops.observed.get(retained); assertArrayEquals(new byte[87], retained);
            }
            assertTrue(residue().isEmpty());
        }
    }
    @Test void collisionsIncludingSymlinkNeverOverwriteAndRetriesAreBounded() throws Exception {
        Files.write(canonical(), bytes(1));
        Path collision = root.resolve(ReplacementStorageFaults.name(0)); Files.write(collision, new byte[]{7});
        Path symlink = root.resolve(ReplacementStorageFaults.name(1)); Files.createSymbolicLink(symlink, Path.of("/dev/zero"));
        var faults = new ReplacementStorageFaults(); faults.deterministicNames = true;
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
        assertEquals(3, faults.names); assertArrayEquals(new byte[]{7}, Files.readAllBytes(collision));
        assertTrue(Files.isSymbolicLink(symlink));
        for (int i = 2; i < 16; i++) Files.write(root.resolve(ReplacementStorageFaults.name(i)), new byte[]{7});
        var exhausted = new ReplacementStorageFaults(); exhausted.deterministicNames = true;
        try (var storage = exhausted.open(root); var stage = storage.stageReplacement(bytes(3))) {
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        assertEquals(16, exhausted.names); assertEquals(0, exhausted.exchanges);
        assertArrayEquals(bytes(2), Files.readAllBytes(canonical())); assertEquals(16, residue().size());
    }
    @Test void privateLinkIdentityMismatchFailsBeforeExchangeAndPreservesForeignEntry() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.afterLink = () -> {
            Files.delete(root.resolve(faults.linkedName)); Files.write(root.resolve(faults.linkedName), bytes(9));
        };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        assertEquals(0, faults.exchanges); assertEquals(0, faults.unlinks);
        assertArrayEquals(bytes(9), Files.readAllBytes(root.resolve(faults.linkedName)));
        assertArrayEquals(bytes(1), Files.readAllBytes(canonical()));
    }
    @Test void absentAndNonregularCanonicalFailBeforeExchange() throws Exception {
        for (String type : List.of("absent", "symlink", "directory", "fifo")) {
            switch (type) {
                case "symlink" -> Files.createSymbolicLink(canonical(), Path.of("/dev/zero"));
                case "directory" -> Files.createDirectory(canonical());
                case "fifo" -> LinuxSecureSourceTest.fifo(canonical());
            }
            var faults = new ReplacementStorageFaults();
            try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
            }
            assertEquals(0, faults.exchanges); assertTrue(residue().isEmpty());
            Files.deleteIfExists(canonical());
        }
    }
    @Test void deletionAfterCanonicalPinCannotBecomeCreation() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.beforeExchange = () -> Files.delete(canonical());
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
            assertEquals(LinuxAbi.ENOENT, assertThrows(LinuxLibc.NativeFailure.class, stage::replaceCanonicalDurably).errno);
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        assertEquals(1, faults.exchanges); assertFalse(Files.exists(canonical())); assertTrue(residue().isEmpty());
    }
    @Test void canonicalSubstitutionsAfterPinAreDetectedWithoutRollbackOrUnexpectedCleanup() throws Exception {
        for (String type : List.of("regular", "symlink", "directory")) {
            Path dir = Files.createDirectory(root.resolve(type)); Path vault = dir.resolve("vault");
            Files.write(vault, bytes(1)); var faults = new ReplacementStorageFaults();
            faults.beforeExchange = () -> {
                Files.delete(vault);
                switch (type) {
                    case "regular" -> Files.write(vault, bytes(9));
                    case "symlink" -> Files.createSymbolicLink(vault, Path.of("/dev/zero"));
                    case "directory" -> Files.write(Files.createDirectory(vault).resolve("child"), bytes(9));
                }
            };
            try (var storage = faults.open(dir); var stage = storage.stageReplacement(bytes(2))) {
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
            }
            assertArrayEquals(bytes(2), Files.readAllBytes(vault)); assertEquals(0, faults.unlinks);
            assertTrue(faults.events.contains("directory-sync"));
            Path unexpected = dir.resolve(faults.linkedName);
            switch (type) {
                case "regular" -> assertArrayEquals(bytes(9), Files.readAllBytes(unexpected));
                case "symlink" -> assertTrue(Files.isSymbolicLink(unexpected));
                case "directory" -> assertArrayEquals(bytes(9), Files.readAllBytes(unexpected.resolve("child")));
            }
        }
    }
    @Test void postExchangeCanonicalSubstitutionIsIncompleteAndLeavesEvidence() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.afterExchange = () -> { Files.delete(canonical()); Files.write(canonical(), bytes(9)); };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        assertArrayEquals(bytes(9), Files.readAllBytes(canonical())); assertEquals(0, faults.unlinks);
        assertArrayEquals(bytes(1), Files.readAllBytes(root.resolve(faults.linkedName)));
        assertTrue(faults.events.contains("directory-sync"));
    }
    @Test void differentCanonicalBeforeImmediatePinNeedsNoExpectedOldCas() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.afterLink = () -> { Files.delete(canonical()); Files.write(canonical(), bytes(9)); };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
        assertArrayEquals(bytes(2), Files.readAllBytes(canonical())); assertTrue(residue().isEmpty());
    }
    @Test void renameAndDurabilityFaultsAreTerminalAndNeverRollback() throws Exception {
        for (String fail : List.of("exchange", "post-exchange-sync", "directory-sync")) {
            Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults(); faults.fail = fail;
            try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
            }
            assertEquals(1, faults.exchanges);
            assertArrayEquals(bytes(fail.equals("exchange") ? 1 : 2), Files.readAllBytes(canonical()));
            if (fail.equals("post-exchange-sync")) assertFalse(faults.events.contains("directory-sync"));
            assertTrue(residue().isEmpty());
        }
    }
    @Test void simulatedAmbiguousRenameErrorDoesNotRetryOrRollBack() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.afterExchange = () -> { throw new IOException("simulated error after real exchange"); };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
            assertThrows(IOException.class, stage::replaceCanonicalDurably);
        }
        assertEquals(1, faults.exchanges); assertArrayEquals(bytes(2), Files.readAllBytes(canonical()));
        assertArrayEquals(bytes(1), Files.readAllBytes(root.resolve(faults.linkedName)));
    }
    @Test void cleanupFailureIsNonGatingAndCloseRechecksBeforeRetry() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults(); faults.fail = "unlink";
        try (var storage = faults.open(root)) {
            var stage = storage.stageReplacement(bytes(2)); stage.replaceCanonicalDurably();
            assertEquals(1, residue().size()); assertTrue(faults.events.contains("directory-sync"));
            faults.fail = ""; stage.close(); stage.close();
            assertEquals(2, faults.unlinks); assertTrue(residue().isEmpty());
        }
        assertArrayEquals(bytes(2), Files.readAllBytes(canonical()));
    }
    @Test void cleanupRecheckPreservesForeignRegularAndSpecialEntriesOrAcceptsAbsence() throws Exception {
        for (String type : List.of("regular", "symlink", "directory", "fifo", "absent")) {
            Path dir = Files.createDirectory(root.resolve(type)); Files.write(dir.resolve("vault"), bytes(1));
            var faults = new ReplacementStorageFaults();
            faults.afterPostSync = () -> {
                Path temp = dir.resolve(faults.linkedName); Files.delete(temp);
                switch (type) {
                    case "regular" -> Files.write(temp, bytes(9));
                    case "symlink" -> Files.createSymbolicLink(temp, Path.of("/dev/zero"));
                    case "directory" -> Files.write(Files.createDirectory(temp).resolve("child"), bytes(9));
                    case "fifo" -> {
                        try { LinuxSecureSourceTest.fifo(temp); }
                        catch (Exception e) { throw new IOException(e); }
                    }
                }
            };
            try (var storage = faults.open(dir); var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
            assertEquals(0, faults.unlinks); assertArrayEquals(bytes(2), Files.readAllBytes(dir.resolve("vault")));
            assertEquals(!type.equals("absent"), Files.exists(dir.resolve(faults.linkedName), LinkOption.NOFOLLOW_LINKS));
        }
    }
    @Test void closeAfterFailedCleanupDoesNotUnlinkSubstitutedResidue() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults(); faults.fail = "unlink";
        try (var storage = faults.open(root)) {
            var stage = storage.stageReplacement(bytes(2)); stage.replaceCanonicalDurably();
            Path temp = root.resolve(faults.linkedName); Files.delete(temp); Files.write(temp, bytes(9));
            faults.fail = ""; stage.close(); assertEquals(1, faults.unlinks);
            assertArrayEquals(bytes(9), Files.readAllBytes(temp));
        }
    }
    @Test void documentedCheckUnlinkRaceCannotBeClaimedAsConditionalDeletion() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.beforeUnlink = () -> {
            Path temp = root.resolve(faults.linkedName);
            Files.move(temp, root.resolve("saved-old")); Files.write(temp, bytes(9));
        };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
        // Explicit evidence of the accepted best-effort boundary, not a safety guarantee.
        assertTrue(residue().isEmpty()); assertArrayEquals(bytes(1), Files.readAllBytes(root.resolve("saved-old")));
        assertArrayEquals(bytes(2), Files.readAllBytes(canonical()));
    }
    @Test void missingNativeSymbolIsLazyAndUnsupportedExchangeHasNoFallback() throws Exception {
        var operations = new LinuxVaultBootstrapStorage.Operations() {
            @Override LinuxLibc libc() { return new LinuxLibc(name -> Optional.empty()); }
        };
        Class.forName(LinuxVaultBootstrapStorage.class.getName());
        try (var storage = LinuxVaultBootstrapStorage.open(root, operations)) {
            try (var initial = storage.stageInitial(bytes(1))) { initial.installInitialDurably(); }
            try (var stage = storage.stageReplacement(bytes(2))) {
                assertEquals("VAULT_REPLACEMENT_UNSUPPORTED", assertThrows(IOException.class, stage::replaceCanonicalDurably).getMessage());
            }
        }
        for (int errno : new int[]{LinuxAbi.EINVAL, LinuxAbi.EOPNOTSUPP, LinuxAbi.EINTR}) {
            var faults = new ReplacementStorageFaults(); faults.exchangeErrno = errno;
            try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
                assertEquals(errno, assertThrows(LinuxLibc.NativeFailure.class, stage::replaceCanonicalDurably).errno);
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
            }
            assertEquals(1, faults.exchanges); assertArrayEquals(bytes(1), Files.readAllBytes(canonical()));
        }
        assertTrue(residue().isEmpty());
        assertEquals(FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, JAVA_INT), LinuxLibc.EXCHANGE_DESCRIPTOR);
        assertEquals(FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT), LinuxLibc.UNLINK_DESCRIPTOR);
        assertEquals(2, LinuxAbi.RENAME_EXCHANGE);
    }
    @Test void rootBindingAndHistoricalHardLinkRemainIntact() throws Exception {
        Path configured = Files.createDirectory(root.resolve("configured")), moved = root.resolve("moved");
        Files.write(configured.resolve("vault"), bytes(1));
        Files.createLink(root.resolve("historical"), configured.resolve("vault"));
        try (var storage = LinuxVaultBootstrapStorage.open(configured)) {
            Files.move(configured, moved); Files.createDirectory(configured);
            Files.write(configured.resolve("vault"), bytes(9));
            try (var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
            assertArrayEquals(bytes(2), Files.readAllBytes(moved.resolve("vault")));
            assertArrayEquals(bytes(9), Files.readAllBytes(configured.resolve("vault")));
        }
        assertArrayEquals(bytes(1), Files.readAllBytes(root.resolve("historical")));
        try (var paths = Files.list(moved)) { assertEquals(List.of("vault"), paths.map(p -> p.getFileName().toString()).toList()); }
    }
    @Test void closeOwnershipIncludesOutstandingStagesAndCallerOwnedReads() throws Exception {
        Files.write(canonical(), bytes(1));
        var storage = LinuxVaultBootstrapStorage.open(root); var stage = storage.stageReplacement(bytes(2));
        try (var read = stage.openRead()) {
            storage.close(); storage.close(); stage.close();
            assertArrayEquals(bytes(2), read.readAllBytes());
        }
        assertThrows(IOException.class, stage::replaceCanonicalDurably); assertThrows(IOException.class, stage::openRead);
        assertThrows(IOException.class, () -> storage.stageReplacement(bytes(2)));
        assertArrayEquals(bytes(1), Files.readAllBytes(canonical())); assertTrue(residue().isEmpty());
        try (var other = LinuxVaultBootstrapStorage.open(root); var initial = other.stageInitial(new byte[0])) {
            assertFalse(initial instanceof VaultBootstrapReplacementStorage.StagedReplacement);
        }
    }
    @Test void unlinkEnoentIsCompletedCleanupAndStorageCloseCleansOwnedNamedStage() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.beforeUnlink = () -> Files.delete(root.resolve(faults.linkedName));
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) { stage.replaceCanonicalDurably(); }
        assertEquals(1, faults.unlinks); assertTrue(residue().isEmpty());
        var failed = new ReplacementStorageFaults(); failed.fail = "exchange";
        var storage = failed.open(root); var stage = storage.stageReplacement(bytes(3));
        assertThrows(IOException.class, stage::replaceCanonicalDurably); assertEquals(1, residue().size());
        storage.close(); storage.close(); stage.close();
        assertTrue(residue().isEmpty()); assertArrayEquals(bytes(2), Files.readAllBytes(canonical()));
        assertThrows(IOException.class, stage::openRead);
    }
    @Test void failedIdentityStabilizationRetainsPrimaryFailureAndAttemptsBothBarriers() throws Exception {
        Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults();
        faults.fail = "post-exchange-sync";
        faults.afterExchange = () -> { Files.delete(canonical()); Files.write(canonical(), bytes(9)); };
        try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
            var failure = assertThrows(IOException.class, stage::replaceCanonicalDurably);
            assertEquals("FD_IDENTITY_MISMATCH", failure.getMessage());
            assertEquals(1, failure.getSuppressed().length);
        }
        assertTrue(faults.events.contains("directory-sync")); assertEquals(0, faults.unlinks);
        assertArrayEquals(bytes(9), Files.readAllBytes(canonical()));
    }
    @Test void socketCanonicalAndResidueAreNotOpenedOrCleanedAsRegularFiles() throws Exception {
        // AF_UNIX has a short pathname limit; this special-file safety fixture is not durability evidence.
        Path shortRoot = Files.createTempDirectory("rewrap-socket-");
        Path vault = shortRoot.resolve("vault");
        try (var socket = java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX)) {
            socket.bind(java.net.UnixDomainSocketAddress.of(vault));
            var faults = new ReplacementStorageFaults();
            try (var storage = faults.open(shortRoot); var stage = storage.stageReplacement(bytes(2))) {
                assertThrows(IOException.class, stage::replaceCanonicalDurably);
                assertThrows(IOException.class, storage::openCanonicalRead);
            }
            assertEquals(0, faults.exchanges); assertTrue(Files.exists(vault));
            Files.delete(vault); Files.write(vault, bytes(1));
            var cleanup = new ReplacementStorageFaults(); cleanup.fail = "unlink";
            try (var storage = cleanup.open(shortRoot);
                 var residueSocket = java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX)) {
                var stage = storage.stageReplacement(bytes(2));
                stage.replaceCanonicalDurably();
                Path residue = shortRoot.resolve(cleanup.linkedName); Files.delete(residue);
                residueSocket.bind(java.net.UnixDomainSocketAddress.of(residue));
                cleanup.fail = ""; stage.close(); assertEquals(1, cleanup.unlinks); assertTrue(Files.exists(residue));
            }
        } finally {
            try (var paths = Files.list(shortRoot)) { for (Path p : paths.toList()) Files.delete(p); }
            Files.delete(shortRoot);
        }
    }
    @Test void concurrentReadersOnlySeeCompleteInodesAndNormalReplacementLeavesNoResidue() throws Exception {
        Files.write(canonical(), bytes(1)); var done = new AtomicBoolean(); var started = new CountDownLatch(1);
        try (var executor = Executors.newSingleThreadExecutor()) {
            var reader = executor.submit(() -> {
                int reads = 0; started.countDown();
                try (var storage = LinuxVaultBootstrapStorage.open(root)) {
                    do {
                        try (var in = storage.openCanonicalRead()) {
                            byte[] observed = in.readAllBytes();
                            assertEquals(87, observed.length);
                            assertTrue(Arrays.equals(bytes(1), observed) || Arrays.equals(bytes(2), observed)); reads++;
                        }
                    } while (!done.get());
                }
                return reads;
            });
            assertTrue(started.await(10, TimeUnit.SECONDS));
            try (var storage = LinuxVaultBootstrapStorage.open(root)) {
                for (int i = 0; i < 150; i++) {
                    try (var stage = storage.stageReplacement(bytes(1 + i % 2))) { stage.replaceCanonicalDurably(); }
                    assertTrue(residue().isEmpty()); assertEquals(87, Files.size(canonical()));
                }
            } finally { done.set(true); }
            assertTrue(reader.get() > 0);
        }
    }
    @Test void descriptorStressIncludingAllTerminalPaths() throws Exception {
        for (int pass = 0; pass < 2; pass++) {
            long before = LinuxVaultBootstrapStorageTest.descriptors();
            for (int i = 0; i < 40; i++) for (String fail : List.of("discard", "none", "collision", "exchange", "post-exchange-sync", "unlink", "delete")) {
                Files.write(canonical(), bytes(1)); var faults = new ReplacementStorageFaults(); faults.fail = fail;
                if (fail.equals("delete")) faults.beforeExchange = () -> Files.delete(canonical());
                if (fail.equals("collision")) {
                    faults.deterministicNames = true; Files.write(root.resolve(ReplacementStorageFaults.name(0)), bytes(9));
                }
                try (var storage = faults.open(root); var stage = storage.stageReplacement(bytes(2))) {
                    if (fail.equals("discard")) continue;
                    if (List.of("exchange", "post-exchange-sync", "delete").contains(fail)) assertThrows(IOException.class, stage::replaceCanonicalDurably);
                    else stage.replaceCanonicalDurably();
                }
                for (Path path : residue()) Files.delete(path);
            }
            if (pass > 0) assertEquals(before, LinuxVaultBootstrapStorageTest.descriptors());
        }
    }
}
