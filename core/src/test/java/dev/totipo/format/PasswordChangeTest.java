package dev.totipo.format;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.io.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.PasswordChangeStatus.*;
import static dev.totipo.format.VaultLifecycleTest.*;
import static dev.totipo.format.LocalEstablishment.Phase.*;

class PasswordChangeTest {
    static final byte[] NEW = CryptoSupport.ascii("new password");
    static byte[] encoded(byte[] password, byte[] root, int seed) {
        return new VaultBootstrapWriter(KDF).encode(password, root,
                VaultBootstrapWriterTest.field(16, seed), VaultBootstrapWriterTest.field(12, seed));
    }
    static Harness established() throws IOException {
        var h = new Harness(); h.local(ESTABLISHED); h.store.canonical = candidate(ROOT);
        h.memory.beforeAppend = () -> fail("Rewrap must never append");
        return h;
    }
    static VaultLifecycle operation(Harness h) {
        return new VaultLifecycle(h.store, h.memory, () -> { throw new AssertionError("No discovery"); }, b -> {
            assertNotEquals(32, b.length, "Must never sample a root"); h.entropy.fill(b);
        }, new VaultBootstrapWriter(KDF), new VaultUnlocker(KDF));
    }
    static void sameJournal(Harness h, byte[] before, SecurityMemoryJournal.Replay replay) {
        assertArrayEquals(before, h.memory.bytes);
        var after = h.replay();
        assertEquals(replay.sequence(), after.sequence()); assertEquals(replay.digest(), after.digest());
        assertEquals(replay.establishment(), after.establishment());
        assertEquals(replay.knowledge().records(), after.knowledge().records());
        assertEquals(replay.knowledge().continuity(), after.knowledge().continuity());
        assertEquals(0, h.snapshots); assertEquals(0, h.contentReads);
    }
    @TestFactory List<DynamicTest> successfulPasswords() {
        var tests = new ArrayList<DynamicTest>();
        for (byte[] next : List.of(NEW, PASSWORD, new byte[0])) {
            tests.add(DynamicTest.dynamicTest("new password length " + next.length, () -> {
                var h = established(); byte[] old = h.store.canonical.clone(), journal = h.memory.bytes.clone();
                var replay = h.replay(); byte[] borrowedOld = PASSWORD.clone(), borrowedNew = next.clone();
                assertEquals(SUCCESS, operation(h).changePassword(borrowedOld, borrowedNew));
                assertArrayEquals(PASSWORD, borrowedOld); assertArrayEquals(next, borrowedNew);
                assertEquals(87, h.store.canonical.length); assertFalse(Arrays.equals(old, h.store.canonical));
                assertFalse(Arrays.equals(Arrays.copyOfRange(old,11,27), Arrays.copyOfRange(h.store.canonical,11,27)));
                assertFalse(Arrays.equals(Arrays.copyOfRange(old,27,39), Arrays.copyOfRange(h.store.canonical,27,39)));
                for (byte[] bytes : List.of(old, h.store.canonical)) {
                    try (var u = new VaultUnlocker(KDF).unlock(bytes, bytes == old ? PASSWORD : next)) {
                        assertArrayEquals(ROOT,u.root()); assertArrayEquals(binding(ROOT),u.binding());
                    }
                }
                if (!Arrays.equals(next,PASSWORD)) {
                    try (var u = new VaultUnlocker(KDF).unlock(h.store.canonical,PASSWORD)) {
                        assertEquals(VaultUnlockResult.Status.AUTHENTICATION_FAILED,u.status());
                    }
                }
                assertEquals(List.of(16,12),h.draws.stream().map(b -> b.length).toList());
                h.draws.forEach(b -> assertArrayEquals(new byte[b.length],b));
                sameJournal(h,journal,replay); assertNull(h.store.residue); assertTrue(h.store.stagedClosed);
                assertEquals(List.of("canonical","replacement-stage","replacement-read","replace","canonical","cleanup"),h.store.events);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> rejectsBeforeEntropyOrStaging() {
        var tests = new ArrayList<DynamicTest>();
        for (String mode : List.of("wrong","auth-corrupt","absent","short","long","magic","version","binding","new-null","new-utf8","new-long","old-invalid")) {
            tests.add(DynamicTest.dynamicTest(mode, () -> {
                var h = established(); byte[] oldPassword = PASSWORD, next = NEW;
                PasswordChangeStatus expected = CURRENT_INVALID_BOOTSTRAP;
                switch (mode) {
                    case "wrong" -> { oldPassword = NEW; expected = CURRENT_AUTHENTICATION_FAILED; }
                    case "auth-corrupt" -> { h.store.canonical[86] ^= 1; expected = CURRENT_AUTHENTICATION_FAILED; }
                    case "absent" -> { h.store.canonical = null; expected = CURRENT_CANONICAL_ABSENT; }
                    case "short" -> h.store.canonical = new byte[86];
                    case "long" -> h.store.canonical = Arrays.copyOf(h.store.canonical,10000);
                    case "magic" -> h.store.canonical[0] ^= 1;
                    case "version" -> h.store.canonical[10] = 2;
                    case "binding" -> { h.store.canonical = candidate(new byte[32]); expected = ESTABLISHED_BINDING_MISMATCH; }
                    case "new-null" -> { next = null; expected = INVALID_NEW_PASSWORD_INPUT; }
                    case "new-utf8" -> { next = new byte[]{(byte)0xff}; expected = INVALID_NEW_PASSWORD_INPUT; }
                    case "new-long" -> { next = new byte[1025]; expected = INVALID_NEW_PASSWORD_INPUT; }
                    case "old-invalid" -> { oldPassword = null; expected = CURRENT_INVALID_PASSWORD_INPUT; }
                }
                byte[] journal = h.memory.bytes.clone(), canonical = h.store.canonical == null ? null : h.store.canonical.clone();
                var replay = h.replay();
                assertEquals(expected,operation(h).changePassword(oldPassword,next));
                assertTrue(h.draws.isEmpty()); assertEquals(0,h.store.stages);
                assertArrayEquals(canonical,h.store.canonical); sameJournal(h,journal,replay);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> replacementFailureMatrix() {
        var tests = new ArrayList<DynamicTest>();
        for (String mode : List.of("stage","staged-read","staged-auth","staged-root","staged-malformed","disappears","replace","ambiguous","canonical-read","canonical-auth","canonical-root","canonical-malformed","canonical-absent")) {
            tests.add(DynamicTest.dynamicTest(mode, () -> {
                var h = established(); byte[] old = h.store.canonical.clone(), journal = h.memory.bytes.clone(); var replay = h.replay();
                switch (mode) {
                    case "stage" -> h.store.fault = FakeBootstrapStorage.Fault.STAGE;
                    case "staged-read" -> h.store.fault = FakeBootstrapStorage.Fault.STAGED_READ;
                    case "staged-auth" -> h.store.stagedSubstitution = encoded(PASSWORD,ROOT,2);
                    case "staged-root" -> h.store.stagedSubstitution = encoded(NEW,new byte[32],2);
                    case "staged-malformed" -> h.store.stagedSubstitution = new byte[88];
                    case "disappears" -> h.store.beforeInstall = () -> h.store.canonical = null;
                    case "replace" -> h.store.fault = FakeBootstrapStorage.Fault.INSTALL;
                    case "ambiguous" -> h.store.fault = FakeBootstrapStorage.Fault.INSTALL_AFTER_PUBLICATION;
                    case "canonical-read" -> h.store.fault = FakeBootstrapStorage.Fault.CANONICAL_READ;
                    case "canonical-auth" -> h.store.installedSubstitution = encoded(PASSWORD,ROOT,2);
                    case "canonical-root" -> h.store.installedSubstitution = encoded(NEW,new byte[32],2);
                    case "canonical-malformed" -> h.store.installedSubstitution = new byte[86];
                    case "canonical-absent" -> h.store.beforeCanonical = () -> { if(h.store.installed) h.store.canonical = null; };
                }
                assertEquals(REWRAP_INCOMPLETE, operation(h).changePassword(PASSWORD,NEW));
                sameJournal(h,journal,replay); assertEquals(1,h.store.stages); assertEquals(2,h.draws.size());
                if (mode.startsWith("stage") || mode.equals("replace")) assertArrayEquals(old,h.store.canonical);
                if (mode.startsWith("stage")) assertFalse(h.store.events.contains("replace"));
                if (mode.equals("disappears") || mode.equals("canonical-absent")) assertNull(h.store.canonical);
                if (mode.equals("ambiguous")) {
                    assertTrue(h.store.installed); assertEquals(1,h.store.reads);
                    try (var u = new VaultUnlocker(KDF).unlock(h.store.canonical,NEW)) { assertArrayEquals(ROOT,u.root()); }
                }
                assertEquals(!mode.equals("stage"),h.store.stagedClosed);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> localPreconditions() {
        var tests = new ArrayList<DynamicTest>();
        for (String mode : List.of("missing","unestablished","pending","zero","corrupt","unsupported","tail")) {
            tests.add(DynamicTest.dynamicTest(mode, () -> {
                var h = new Harness(); PasswordChangeStatus expected = LOCAL_SECURITY_MEMORY_INVALID;
                switch(mode) {
                    case "missing" -> expected = LOCAL_SECURITY_MEMORY_MISSING;
                    case "unestablished" -> { h.local(UNESTABLISHED); expected = LOCAL_STATE_NOT_ESTABLISHED; }
                    case "pending" -> { h.local(PENDING); expected = LOCAL_STATE_NOT_ESTABLISHED; }
                    case "zero" -> h.memory.bytes = new byte[0];
                    case "corrupt" -> { h.local(ESTABLISHED); h.memory.bytes[h.memory.bytes.length-1] ^= 1; }
                    case "unsupported" -> { h.local(ESTABLISHED); h.memory.bytes[11] = 2; }
                    case "tail" -> { h.local(ESTABLISHED); h.memory.bytes = Arrays.copyOf(h.memory.bytes,h.memory.bytes.length+1); expected = LOCAL_TAIL_REPAIR_REQUIRED; }
                }
                byte[] before = h.memory.bytes == null ? null : h.memory.bytes.clone();
                assertEquals(expected,operation(h).changePassword(PASSWORD,NEW));
                assertArrayEquals(before,h.memory.bytes); assertTrue(h.store.events.isEmpty()); assertTrue(h.draws.isEmpty());
            }));
        }
        return tests;
    }
    @Test void writerAndSelfVerificationFailuresNeverStage() throws Exception {
        for (boolean throwsError : List.of(true,false)) {
            var h = established(); byte[] before = h.memory.bytes.clone();
            Argon2idKdf broken = (p,s) -> { if (throwsError) throw new IllegalStateException(); return new byte[32]; };
            var lifecycle = new VaultLifecycle(h.store,h.memory,h.source,h.entropy,new VaultBootstrapWriter(broken),new VaultUnlocker(KDF));
            assertEquals(CRYPTO_CONSTRUCTION_FAILED,lifecycle.changePassword(PASSWORD,NEW));
            assertEquals(0,h.store.stages); assertArrayEquals(candidate(ROOT),h.store.canonical); assertArrayEquals(before,h.memory.bytes);
            h.draws.forEach(b -> assertArrayEquals(new byte[b.length],b));
        }
    }
    @Test void cleanupFailureAndEquivalentConcurrentRepresentationAreAccepted() throws Exception {
        var h = established(); h.store.fault = FakeBootstrapStorage.Fault.CLEANUP;
        h.store.installedSubstitution = encoded(NEW,ROOT,9);
        h.store.collision = candidate(new byte[32]); // A different canonical races before our replacement; no CAS.
        assertEquals(SUCCESS,operation(h).changePassword(PASSWORD,NEW));
        assertArrayEquals(h.store.installedSubstitution,h.store.canonical); assertNotNull(h.store.residue);
        assertEquals(1,Collections.frequency(h.store.events,"replace"));
    }
    @Test void replacementStageOwnsStableBytesAndNeverDeletesCanonical() throws Exception {
        var store = new FakeBootstrapStorage(); store.canonical = candidate(ROOT);
        byte[] bytes = encoded(NEW,ROOT,2), exact = bytes.clone();
        try (var staged = store.stageReplacement(bytes)) {
            bytes[0] ^= 1; assertArrayEquals(exact,VaultLifecycle.read(staged.openRead()));
            assertArrayEquals(candidate(ROOT),store.canonical);
            staged.replaceCanonicalDurably(); assertArrayEquals(exact,store.canonical);
            assertThrows(IOException.class,staged::replaceCanonicalDurably);
        }
        assertArrayEquals(exact,store.canonical); assertNull(store.residue);
        try (var staged = store.stageReplacement(bytes)) { assertArrayEquals(bytes,VaultLifecycle.read(staged.openRead())); }
        assertArrayEquals(exact,store.canonical); assertNull(store.residue);
    }

    @Test void unknownContinuityAndActiveOpaqueEvidencePreserveExactJournalAndGraph() throws Exception {
        for (boolean unknown : List.of(false,true)) {
            var h = established(); h.memory.beforeAppend = () -> {};
            var session = SecurityMemorySession.open(h.memory);
            session.commitRecord(SecurityMemoryJournalTest.token(1));
            session.commitRecord(SecurityMemoryJournalTest.device(4,1));
            session.commitRecord(SecurityMemoryJournalTest.opaque(3));
            if (unknown) assertTrue(session.markUnknown());
            byte[] journal = h.memory.bytes.clone(); var before = h.replay();
            assertEquals(unknown ? LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN
                    : LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN,before.knowledge().continuity());
            assertEquals(3,before.knowledge().size());
            h.memory.beforeAppend = () -> fail("No append even with UNKNOWN/opaque evidence");
            assertEquals(SUCCESS,operation(h).changePassword(PASSWORD,NEW));
            sameJournal(h,journal,before);
        }
    }

    @Test void productionArgon2WriterAndReaderRewrapSameRoot() throws Exception {
        var h = established();
        h.store.canonical = new VaultBootstrapWriter().encode(PASSWORD,ROOT,new byte[16],new byte[12]);
        assertEquals(SUCCESS,new VaultLifecycle(h.store,h.memory,h.source,h.entropy,
                new VaultBootstrapWriter(),new VaultUnlocker()).changePassword(PASSWORD,NEW));
        try (var u = new VaultUnlocker().unlock(h.store.canonical,NEW)) {
            assertArrayEquals(ROOT,u.root()); assertArrayEquals(binding(ROOT),u.binding());
        }
        assertEquals(0,h.snapshots);
    }

    @Test void entropyFailureDoesNotStageOrRetainDraws() throws Exception {
        var h = established(); byte[] journal = h.memory.bytes.clone();
        var lifecycle = new VaultLifecycle(h.store,h.memory,h.source,b -> {
            assertNotEquals(32,b.length); h.entropy.fill(b); throw new IllegalStateException("Entropy unavailable");
        },new VaultBootstrapWriter(KDF),new VaultUnlocker(KDF));
        assertEquals(CRYPTO_CONSTRUCTION_FAILED,lifecycle.changePassword(PASSWORD,NEW));
        assertEquals(0,h.store.stages); assertArrayEquals(candidate(ROOT),h.store.canonical);
        assertArrayEquals(journal,h.memory.bytes); h.draws.forEach(b -> assertArrayEquals(new byte[b.length],b));
    }

    private static SecurityMemoryStorage readOnlyMemory(Harness h, boolean failRead) {
        return new SecurityMemoryStorage() {
            public InputStream openRead() throws IOException {
                if (failRead) throw new IOException("Unavailable local memory");
                h.store.events.add("local-replay");
                return h.memory.openRead();
            }
            public void initializeDurably(byte[] b) { fail("No initialize"); }
            public void appendDurably(byte[] b) { fail("No append"); }
            public void truncateDurably(long n) { fail("No repair"); }
            public void close() { fail("Borrowed store"); }
        };
    }

    @Test void fullOrderingWithReadOnlyMemoryAndNoDiscovery() throws Exception {
        var h = established(); int[] unlocks = {0};
        Argon2idKdf reader = (p,s) -> {
            h.store.events.add(switch (++unlocks[0]) {
                case 1 -> "current-unlock";
                case 2 -> "self-unlock";
                case 3 -> "staged-unlock";
                case 4 -> "canonical-unlock";
                default -> throw new AssertionError("Unexpected unlock");
            });
            assertArrayEquals(unlocks[0] == 1 ? PASSWORD : NEW,p);
            return KDF.derive(p,s);
        };
        Argon2idKdf writer = (p,s) -> { h.store.events.add("encode"); return KDF.derive(p,s); };
        var lifecycle = new VaultLifecycle(h.store,readOnlyMemory(h,false),
                () -> { throw new AssertionError("No semantic scan"); }, b -> {
                    assertEquals(ESTABLISHED,h.replay().establishment().phase());
                    assertEquals(1,unlocks[0]); // Auth and binding preconditions passed before entropy.
                    assertNotEquals(32,b.length); h.store.events.add("entropy-" + b.length); h.entropy.fill(b);
                }, new VaultBootstrapWriter(writer),new VaultUnlocker(reader));
        assertEquals(SUCCESS,lifecycle.changePassword(PASSWORD,NEW));
        assertEquals(List.of("local-replay","canonical","current-unlock","entropy-16","entropy-12",
                "encode","self-unlock","replacement-stage","replacement-read","staged-unlock",
                "replace","canonical","canonical-unlock","cleanup"),h.store.events);
    }

    @Test void unsupportedCapabilityAndReadIoAreExplicit() throws Exception {
        var h = established();
        var initialOnly = new VaultBootstrapStorage() {
            public InputStream openCanonicalRead() { throw new AssertionError("Unsupported must stop early"); }
            public StagedBootstrap stageInitial(byte[] b) { throw new AssertionError("Never initial staging"); }
            public void close() { fail("Borrowed store"); }
        };
        assertEquals(REPLACEMENT_UNSUPPORTED,new VaultLifecycle(initialOnly,h.memory,h.source)
                .changePassword(PASSWORD,NEW));
        assertEquals(LOCAL_STORAGE_UNAVAILABLE,new VaultLifecycle(h.store,readOnlyMemory(h,true),h.source)
                .changePassword(PASSWORD,NEW));
        h.store.installed = true; h.store.fault = FakeBootstrapStorage.Fault.CANONICAL_READ;
        assertEquals(BOOTSTRAP_STORAGE_UNAVAILABLE,operation(h).changePassword(PASSWORD,NEW));
        assertEquals(0,h.store.stages); assertTrue(h.draws.isEmpty());
    }

    @Test void malformedCurrentNeverRunsKdf() throws Exception {
        for (int mode = 0; mode < 3; mode++) {
            var h = established();
            if (mode == 0) h.store.canonical = new byte[88];
            if (mode == 1) h.store.canonical[0] ^= 1;
            if (mode == 2) h.store.canonical[10] = 2;
            var lifecycle = new VaultLifecycle(h.store,h.memory,h.source,h.entropy,new VaultBootstrapWriter(KDF),
                    new VaultUnlocker((p,s) -> { throw new AssertionError("Preflight before Argon2"); }));
            assertEquals(CURRENT_INVALID_BOOTSTRAP,lifecycle.changePassword(PASSWORD,NEW));
        }
    }

    @Test void allBootstrapReadsAreBoundedAndClosed() throws Exception {
        for (String boundary : List.of("current","staged","canonical")) {
            var h = established(); int[] reads = {0}, consumed = {0}, closed = {0};
            var storage = new VaultBootstrapReplacementStorage() {
                InputStream overlong() {
                    return new InputStream() {
                        public int read() { assertTrue(++consumed[0] <= 88); return 0; }
                        public void close() { closed[0]++; }
                    };
                }
                public InputStream openCanonicalRead() throws IOException {
                    reads[0]++;
                    return boundary.equals("current") || boundary.equals("canonical") && reads[0] == 2
                            ? overlong() : h.store.openCanonicalRead();
                }
                public StagedBootstrap stageInitial(byte[] b) { throw new AssertionError(); }
                public StagedReplacement stageReplacement(byte[] b) throws IOException {
                    var delegate = h.store.stageReplacement(b);
                    return new StagedReplacement() {
                        public InputStream openRead() throws IOException { return boundary.equals("staged") ? overlong() : delegate.openRead(); }
                        public void replaceCanonicalDurably() throws IOException { delegate.replaceCanonicalDurably(); }
                        public void close() throws IOException { delegate.close(); }
                    };
                }
                public void close() { fail("Borrowed store"); }
            };
            var lifecycle = new VaultLifecycle(storage,h.memory,h.source,h.entropy,new VaultBootstrapWriter(KDF),new VaultUnlocker(KDF));
            assertEquals(boundary.equals("current") ? CURRENT_INVALID_BOOTSTRAP : REWRAP_INCOMPLETE,
                    lifecycle.changePassword(PASSWORD,NEW));
            assertEquals(88,consumed[0]); assertEquals(1,closed[0]);
        }
    }
}
