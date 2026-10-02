package org.totipo.api;

import org.totipo.*;
import org.totipo.spi.*;
import org.totipo.testing.MemoryVault;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.EnumSource;
import static org.junit.jupiter.api.Assertions.*;

/** Exercise the public application through only the layout SPI, including dishonest staging
 * and unchecked failures after canonical mutation entry. */
class SpiApplicationTest {
    private static byte[] template;
    private static final char[] PASSWORD = "password".toCharArray();
    @BeforeAll static void template() {
        var memory = new MemoryVault();
        try (var session = memory.create()) { template = memory.bootstrap.clone(); assertNotNull(session.fingerprint()); }
    }
    private static final class Store implements TotipoStore {
        byte[] vault = template.clone();
        final Map<ObjectName, byte[]> objects = new ConcurrentHashMap<>();
        final List<ObjectName> reads = Collections.synchronizedList(new ArrayList<>());
        int closes, installs, replaces, preparedCloses, publications;
        String stageMode = "", installMode = "", replaceMode = "", publicationMode = "";
        boolean incomplete, failCleanup;
        BoundedRead forcedRead;
        BoundedRead forcedObjectRead;
        EntryKind scanKind = EntryKind.REGULAR;
        Runnable afterReadBack = () -> {};
        static BoundedRead read(byte[] bytes, int expected) {
            if (bytes == null) return new BoundedRead.Absent();
            if (bytes.length < expected) return new BoundedRead.Undersized(bytes.length);
            if (bytes.length > expected) return new BoundedRead.Oversized();
            return new BoundedRead.Present(bytes);
        }
        @Override public BoundedRead readVault(int expected) { return forcedRead == null ? read(vault, expected) : forcedRead; }
        @Override public ObjectScan scanObjects() {
            var entries = objects.entrySet().stream().map(e -> new ObjectEntry(e.getKey(), scanKind,
                    OptionalLong.of(999999))).toList(); // Deliberately stale metadata must not size the read.
            return incomplete ? new ObjectScan.Incomplete(entries, StoreFailure.UNAVAILABLE) : new ObjectScan.Complete(entries);
        }
        @Override public BoundedRead readObject(ObjectName name, int expected) {
            assertEquals(1024, expected); reads.add(name);
            return forcedObjectRead == null ? read(objects.get(name), expected) : forcedObjectRead;
        }
        @Override public ObjectWrite publishObject(ObjectName name, byte[] bytes) {
            publications++;
            if (publicationMode.equals("failed")) return new ObjectWrite.Failed(StoreFailure.UNAVAILABLE);
            var old = objects.putIfAbsent(name, bytes.clone());
            if (publicationMode.equals("throw")) throw new IllegalStateException("lost acknowledgement");
            if (publicationMode.equals("uncertain")) return new ObjectWrite.Uncertain(StoreFailure.UNAVAILABLE);
            if (old == null) return new ObjectWrite.Written();
            return Arrays.equals(old, bytes) ? new ObjectWrite.AlreadyPresentExact() : new ObjectWrite.ExistingDifferent();
        }
        @Override public VaultPrepare prepareVault(byte[] bytes) {
            if (stageMode.equals("failed")) return new VaultPrepare.Failed(StoreFailure.UNAVAILABLE);
            byte[] staged = bytes.clone();
            if (stageMode.equals("changed")) staged[0] ^= 1;
            return new VaultPrepare.Prepared(new PreparedVault() {
                boolean closed;
                @Override public BoundedRead readBack(int expected) {
                    var result = switch (stageMode) {
                        case "short" -> new BoundedRead.Undersized(expected - 1);
                        case "long" -> new BoundedRead.Oversized();
                        case "unavailable" -> new BoundedRead.Unavailable(StoreFailure.UNAVAILABLE);
                        case "wrong-kind" -> new BoundedRead.WrongKind(EntryKind.SYMLINK);
                        default -> read(staged, expected);
                    };
                    afterReadBack.run();
                    return result;
                }
                @Override public VaultInstall installCanonicalIfAbsent() {
                    installs++;
                    if (installMode.equals("failed")) return new VaultInstall.Failed(StoreFailure.UNAVAILABLE);
                    if (installMode.equals("already") || vault != null) return new VaultInstall.AlreadyPresent();
                    vault = staged.clone();
                    if (installMode.equals("throw")) throw new IllegalStateException("lost install acknowledgement");
                    if (installMode.equals("uncertain")) return new VaultInstall.Uncertain(StoreFailure.UNAVAILABLE);
                    return new VaultInstall.Installed();
                }
                @Override public VaultReplace replaceCanonical() {
                    replaces++;
                    if (replaceMode.equals("failed")) return new VaultReplace.Failed(StoreFailure.UNAVAILABLE);
                    vault = staged.clone();
                    if (replaceMode.equals("throw")) throw new IllegalStateException("lost replacement acknowledgement");
                    if (replaceMode.equals("uncertain")) return new VaultReplace.Uncertain(StoreFailure.UNAVAILABLE);
                    return new VaultReplace.Replaced();
                }
                @Override public void close() {
                    if (!closed) {
                        closed = true; preparedCloses++;
                        if (failCleanup) throw new IllegalStateException("staging cleanup failed");
                    }
                }
            });
        }
        @Override public void close() { closes++; }
    }
    private static VaultSession open(Store store) {
        return assertInstanceOf(OpenResult.Opened.class, Totipo.open(store, PASSWORD)).session();
    }

    @Test void successfulOpenTransfersOwnershipAndSessionClosesExactlyOnce() {
        var store = new Store();
        var session = open(store);
        assertEquals(0, store.closes);
        PublicApiTest.finished(session);
        session.close(); session.close();
        assertEquals(1, store.closes);
    }

    @Test void successfulCreateTransfersOwnershipAndClosesStage() {
        var store = new Store(); store.vault = null;
        var session = assertInstanceOf(CreateVaultResult.Created.class, Totipo.create(store, PASSWORD)).session();
        assertEquals(0, store.closes); assertEquals(1, store.preparedCloses);
        assertEquals(1, store.installs);
        session.close(); session.close();
        assertEquals(1, store.closes);
    }

    @ParameterizedTest @ValueSource(strings = {"absent", "short", "long", "wrong-kind", "unavailable", "password"})
    void unsuccessfulOpenClosesTransferredStoreAndPreservesTaxonomy(String mode) {
        var store = new Store();
        store.forcedRead = switch (mode) {
            case "absent" -> new BoundedRead.Absent();
            case "short" -> new BoundedRead.Undersized(1);
            case "long" -> new BoundedRead.Oversized();
            case "wrong-kind" -> new BoundedRead.WrongKind(EntryKind.DIRECTORY);
            case "unavailable" -> new BoundedRead.Unavailable(StoreFailure.UNAVAILABLE);
            default -> null;
        };
        var result = Totipo.open(store, "wrong password".toCharArray());
        switch (mode) {
            case "absent" -> assertInstanceOf(OpenResult.Absent.class, result);
            case "short", "long" -> assertInstanceOf(OpenResult.InvalidVault.class, result);
            case "password" -> assertInstanceOf(OpenResult.AuthenticationFailed.class, result);
            default -> assertInstanceOf(OpenResult.Unavailable.class, result);
        }
        assertEquals(1, store.closes);
    }

    @Test void invalidPasswordStillClosesTransferredStore() {
        var store = new Store();
        assertThrows(NullPointerException.class, () -> Totipo.open(store, null));
        assertEquals(1, store.closes);
        var create = new Store(); create.vault = null;
        assertThrows(NullPointerException.class, () -> Totipo.create(create, null));
        assertEquals(1, create.closes);
    }

    @ParameterizedTest @ValueSource(strings = {"failed", "changed", "short", "long", "wrong-kind", "unavailable"})
    void createValidatesWhatWasStagedBeforeAnyCanonicalMutation(String mode) {
        var store = new Store(); store.vault = null; store.stageMode = mode;
        assertInstanceOf(CreateVaultResult.Failed.class, Totipo.create(store, PASSWORD));
        assertEquals(0, store.installs); assertNull(store.vault); assertEquals(1, store.closes);
        assertEquals(mode.equals("failed") ? 0 : 1, store.preparedCloses);
    }

    @ParameterizedTest @ValueSource(strings = {"failed", "already", "uncertain", "throw"})
    void createMapsDefiniteAndAmbiguousInstallOutcomes(String mode) {
        var store = new Store(); store.vault = null; store.installMode = mode;
        var result = Totipo.create(store, PASSWORD);
        if (mode.equals("failed")) assertInstanceOf(CreateVaultResult.Failed.class, result);
        else if (mode.equals("already")) assertInstanceOf(CreateVaultResult.AlreadyExists.class, result);
        else assertInstanceOf(CreateVaultResult.Uncertain.class, result);
        assertEquals(1, store.installs); assertEquals(1, store.closes); assertEquals(1, store.preparedCloses);
    }

    @ParameterizedTest @ValueSource(strings = {"failed", "uncertain", "throw", "success"})
    void passwordChangeMapsReplacementCertainty(String mode) {
        var store = new Store(); store.replaceMode = mode;
        try (var session = open(store)) {
            var result = session.changePassword(PASSWORD, "next".toCharArray());
            assertEquals(switch (mode) {
                case "failed" -> PasswordChangeResult.FAILED;
                case "uncertain", "throw" -> PasswordChangeResult.UNCERTAIN;
                default -> PasswordChangeResult.CHANGED;
            }, result);
            assertEquals(1, store.replaces); assertEquals(1, store.preparedCloses);
            assertEquals(0, store.closes);
        }
        assertEquals(1, store.closes);
    }

    @ParameterizedTest @ValueSource(strings = {"changed", "absent", "unavailable", "stage-changed"})
    void currentComparisonAndStageValidationRemainInCore(String mode) {
        var store = new Store();
        try (var session = open(store)) {
            if (mode.equals("stage-changed")) store.stageMode = "changed";
            else store.afterReadBack = () -> {
                if (mode.equals("changed")) { store.vault = store.vault.clone(); store.vault[0] ^= 1; }
                if (mode.equals("absent")) store.vault = null;
                if (mode.equals("unavailable")) store.forcedRead = new BoundedRead.Unavailable(StoreFailure.UNAVAILABLE);
            };
            assertEquals(mode.equals("changed") ? PasswordChangeResult.STALE : PasswordChangeResult.FAILED,
                    session.changePassword(PASSWORD, "next".toCharArray()));
            assertEquals(0, store.replaces); assertEquals(1, store.preparedCloses);
        }
    }

    @ParameterizedTest @ValueSource(strings = {"uncertain", "throw"})
    void publicationUncertaintyIsMonotonicUntilPositiveExactRetry(String mode) {
        var store = new Store();
        try (var session = open(store); var secret = NewSecret.copyOf(new byte[]{1, 2, 3});
             var create = session.state().createToken()) {
            store.publicationMode = mode;
            var uncertain = assertInstanceOf(SaveResult.PublicationUncertain.class, create.secret(secret).save());
            assertEquals(1, store.objects.size());
            store.publicationMode = "failed";
            var again = assertInstanceOf(SaveResult.PublicationUncertain.class, uncertain.retry().retryPublication());
            store.publicationMode = "";
            assertInstanceOf(SaveResult.Saved.class, again.retry().retryPublication());
            assertEquals(1, store.objects.size()); assertEquals(3, store.publications);
        }
    }

    @Test void coreFiltersProtocolNamesAndUsesIncompleteObservationsWithoutTrustingMetadata() {
        var initial = new Store();
        try (var session = open(initial); var secret = NewSecret.copyOf(new byte[]{1, 2, 3});
             var create = session.state().createToken()) {
            assertInstanceOf(SaveResult.Saved.class, create.secret(secret).save());
            PublicApiTest.refresh(session);
        }
        var store = new Store(); store.objects.putAll(initial.objects);
        var canonical = store.objects.keySet().iterator().next();
        var junk = new ObjectName("junk");
        var upper = new ObjectName(canonical.value().toUpperCase(Locale.ROOT));
        store.objects.put(junk, new byte[]{4}); store.objects.put(upper, store.objects.get(canonical));
        store.reads.clear(); store.incomplete = true;
        try (var session = open(store)) {
            var state = PublicApiTest.finished(session);
            assertEquals(1, state.tokens().size());
            assertTrue(store.reads.contains(canonical));
            assertFalse(store.reads.contains(junk)); assertFalse(store.reads.contains(upper));
            assertFalse(state.diagnostics().isEmpty());
        }
        assertEquals(1, store.closes);
    }

    @Test void stagingCleanupFailureDoesNotDowngradeAcknowledgedCanonicalMutation() {
        var store = new Store(); store.vault = null; store.failCleanup = true;
        try (var session = assertInstanceOf(CreateVaultResult.Created.class, Totipo.create(store, PASSWORD)).session()) {
            assertEquals(1, store.preparedCloses);
            assertEquals(PasswordChangeResult.CHANGED, session.changePassword(PASSWORD, "next".toCharArray()));
            assertEquals(2, store.preparedCloses);
        }
        assertEquals(1, store.closes);
    }

    @ParameterizedTest @EnumSource(EntryKind.class)
    void everyCanonicalScanKindGetsFreshReadAndWrongKindEvidence(EntryKind kind) {
        var store = new Store();
        var canonical = new ObjectName("ab".repeat(32));
        store.objects.put(canonical, new byte[1024]);
        store.objects.put(new ObjectName("junk"), new byte[0]);
        store.objects.put(new ObjectName(".tmp"), new byte[0]);
        store.objects.put(new ObjectName("a".repeat(63)), new byte[0]);
        store.scanKind = kind;
        store.forcedObjectRead = new BoundedRead.WrongKind(kind == EntryKind.REGULAR ? EntryKind.SYMLINK : kind);
        try (var session = open(store)) {
            var state = PublicApiTest.finished(session);
            assertEquals(List.of(canonical), store.reads);
            assertTrue(state.tokens().isEmpty());
            assertEquals(List.of(new VaultDiagnostic("UNAVAILABLE")), state.diagnostics());
        }
    }

    @ParameterizedTest @EnumSource(value = EntryKind.class, names = {"SYMLINK", "DIRECTORY", "OTHER", "UNKNOWN"})
    void nonRegularScanKindCanBecomeValidAtFreshRead(EntryKind kind) {
        var initial = new Store();
        try (var session = open(initial); var secret = NewSecret.copyOf(new byte[]{1, 2, 3});
             var create = session.state().createToken()) {
            assertInstanceOf(SaveResult.Saved.class, create.secret(secret).save());
        }
        var store = new Store(); store.objects.putAll(initial.objects); store.scanKind = kind;
        store.objects.put(new ObjectName("junk"), new byte[0]);
        try (var session = open(store)) {
            var state = PublicApiTest.finished(session);
            assertEquals(1, state.tokens().size());
            assertTrue(state.diagnostics().isEmpty());
            assertEquals(List.copyOf(initial.objects.keySet()), store.reads);
        }
    }
}
