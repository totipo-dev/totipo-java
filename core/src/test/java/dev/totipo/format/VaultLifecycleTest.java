package dev.totipo.format;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;
import java.io.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultLifecycleResult.Status.*;
import static dev.totipo.format.LocalEstablishment.Phase.*;

class VaultLifecycleTest {
    // Cheap KDF only for ordering tests; writer interoperability uses production Argon2 separately.
    static final Argon2idKdf KDF = (p,s) -> CryptoSupport.sha256(p,s);
    static final byte[] PASSWORD = CryptoSupport.ascii("password");
    static final byte[] ROOT = VaultBootstrapWriterTest.field(32, 1);
    static byte[] candidate(byte[] root) { return new VaultBootstrapWriter(KDF).encode(PASSWORD, root, new byte[16], new byte[12]); }
    static byte[] binding(byte[] root) {
        try (var u = VaultUnlockResult.unlocked(root)) { return u.binding(); }
    }
    static final class Harness {
        final MemoryJournalStorage memory = new MemoryJournalStorage();
        final FakeBootstrapStorage store = new FakeBootstrapStorage();
        final List<byte[]> draws = new ArrayList<>();
        int snapshots, closedSnapshots, contentReads;
        boolean preflightCandidate, preflightIncomplete, discoveryIncomplete, appearAfterPreflight;
        final DiscoverySource source = () -> {
            snapshots++;
            boolean preflight = snapshots == 1 && memory.appends == 0;
            if (!preflight) { assertEquals(ESTABLISHED, replay().establishment().phase()); }
            var candidates = new ArrayList<DiscoverySource.Candidate>();
            if (preflight && preflightCandidate || !preflight && appearAfterPreflight) {
                candidates.add(new DiscoverySource.Candidate(new ObjectId(new byte[32]), () -> {
                    contentReads++; assertEquals(ESTABLISHED, replay().establishment().phase());
                    return java.nio.channels.Channels.newChannel(new ByteArrayInputStream(new byte[0]));
                }));
            }
            return new DiscoverySource.Snapshot(candidates,
                    (preflight ? preflightIncomplete : discoveryIncomplete)
                            ? DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE : DiscoverySource.SnapshotIssue.NONE,
                    () -> closedSnapshots++);
        };
        final EntropySource entropy = b -> {
            draws.add(b); System.arraycopy(VaultBootstrapWriterTest.field(b.length, 1), 0, b, 0, b.length);
        };
        VaultLifecycle lifecycle() { return new VaultLifecycle(store,memory,source,entropy,new VaultBootstrapWriter(KDF),new VaultUnlocker(KDF)); }
        SecurityMemoryJournal.Replay replay() {
            try { return SecurityMemoryJournal.replay(memory.openRead()); }
            catch (IOException e) { throw new AssertionError(e); }
        }
        void local(LocalEstablishment.Phase phase) throws IOException {
            var s = SecurityMemorySession.initializeNew(memory);
            if (phase == PENDING) { assertTrue(s.persistPending(binding(ROOT))); }
            if (phase == ESTABLISHED) { assertTrue(s.establishFirstOpen(binding(ROOT))); }
        }
        void failed(VaultLifecycleResult result, VaultLifecycleResult.Status expected) {
            try (result) {
                assertEquals(expected,result.status()); assertNull(result.root()); assertNull(result.discovery());
            }
            assertEquals(0,contentReads);
        }
    }

    @Test void cleanCreationOrdersEveryBoundaryAndOwnsSecrets() throws Exception {
        var h=new Harness();
        h.store.beforeStage=()-> { assertEquals(PENDING,h.replay().establishment().phase()); assertEquals(1,h.replay().sequence()); assertNull(h.store.canonical); };
        h.store.beforeInstall=()-> { assertEquals(PENDING,h.replay().establishment().phase()); assertTrue(h.store.events.contains("staged-read")); };
        h.memory.beforeAppend=()-> {
            if (h.memory.appends==1) { assertNotNull(h.store.canonical); assertEquals(2,h.store.reads); assertFalse(h.store.stagedClosed); }
        };
        var result=h.lifecycle().createNew(PASSWORD);
        assertEquals(CREATED_ESTABLISHED,result.status()); assertEquals(ESTABLISHED,h.replay().establishment().phase());
        assertEquals(2,h.replay().sequence()); assertEquals(230,h.memory.bytes.length);
        assertEquals(1,h.memory.bytes[24]); assertEquals(2,h.memory.bytes[133]);
        assertEquals(List.of(32,16,12),h.draws.stream().map(b->b.length).toList());
        assertNotSame(h.draws.get(0),h.draws.get(1));
        h.draws.forEach(b->assertArrayEquals(new byte[b.length],b));
        assertArrayEquals(ROOT,result.root()); byte[] copy=result.root(); copy[0]^=1; assertArrayEquals(ROOT,result.root());
        assertFalse(result.toString().contains(HexFormat.of().formatHex(ROOT)));
        assertEquals(2,h.snapshots); assertEquals(2,h.closedSnapshots);
        assertFalse(h.store.closed); // caller owns both stores
        result.close(); assertThrows(IllegalStateException.class,result::root);
    }
    @TestFactory List<DynamicTest> creationPreconditions() {
        var tests=new ArrayList<DynamicTest>();
        for (String mode:List.of("canonical","candidates","incomplete","pending","established")) {
            tests.add(DynamicTest.dynamicTest(mode,()-> {
                var h=new Harness(); var expected=LOCAL_STATE_NOT_FRESH;
                switch(mode) {
                    case "canonical" -> {h.store.canonical=candidate(ROOT); expected=CANONICAL_VAULT_PRESENT;}
                    case "candidates" -> {h.preflightCandidate=true; expected=CREATE_BLOCKED_EXISTING_OBJECT_CANDIDATES;}
                    case "incomplete" -> {h.preflightIncomplete=true; expected=CREATE_BLOCKED_DISCOVERY_INCOMPLETE;}
                    case "pending" -> h.local(PENDING);
                    case "established" -> h.local(ESTABLISHED);
                }
                byte[] before=h.memory.bytes==null?null:h.memory.bytes.clone();
                h.failed(h.lifecycle().createNew(PASSWORD),expected);
                assertArrayEquals(before,h.memory.bytes); assertTrue(h.draws.isEmpty()); assertEquals(0,h.store.stages);
                assertEquals(h.snapshots,h.closedSnapshots);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> publicationFailuresLeavePending() {
        var tests=new ArrayList<DynamicTest>();
        for (String mode:List.of("stage","staged-read","staged-auth","staged-root","collision","install",
                "ambiguous-install","canonical-read","canonical-auth","canonical-malformed","canonical-root")) {
            tests.add(DynamicTest.dynamicTest(mode,()-> {
                var h=new Harness(); byte[] other=candidate(new byte[32]);
                switch(mode) {
                    case "stage" -> h.store.fault=FakeBootstrapStorage.Fault.STAGE;
                    case "staged-read" -> h.store.fault=FakeBootstrapStorage.Fault.STAGED_READ;
                    case "staged-auth" -> {h.store.stagedSubstitution=candidate(ROOT); h.store.stagedSubstitution[86]^=1;}
                    case "staged-root" -> h.store.stagedSubstitution=other;
                    case "collision" -> h.store.collision=other;
                    case "install" -> h.store.fault=FakeBootstrapStorage.Fault.INSTALL;
                    case "ambiguous-install" -> h.store.fault=FakeBootstrapStorage.Fault.INSTALL_AFTER_PUBLICATION;
                    case "canonical-read" -> h.store.fault=FakeBootstrapStorage.Fault.CANONICAL_READ;
                    case "canonical-auth" -> {h.store.installedSubstitution=candidate(ROOT); h.store.installedSubstitution[86]^=1;}
                    case "canonical-malformed" -> h.store.installedSubstitution=new byte[86];
                    case "canonical-root" -> h.store.installedSubstitution=other;
                }
                h.failed(h.lifecycle().createNew(PASSWORD),PUBLICATION_INCOMPLETE);
                assertEquals(PENDING,h.replay().establishment().phase()); assertEquals(1,h.replay().sequence());
                assertEquals(1,h.snapshots); assertEquals(3,h.draws.size());
                if (mode.equals("collision")) { assertArrayEquals(other,h.store.canonical); assertEquals(1,h.store.reads); }
                else if (mode.startsWith("staged") || mode.equals("stage") || mode.equals("install")) { assertNull(h.store.canonical); }
                else { assertNotNull(h.store.canonical); }
                if (!mode.equals("stage")) { assertTrue(h.store.stagedClosed); }
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> postInstallCleanupFailureDoesNotGateEstablishmentOrDiscovery() {
        var tests = new ArrayList<DynamicTest>();
        for (boolean incomplete : List.of(false, true)) {
            tests.add(DynamicTest.dynamicTest("cleanup failure, discovery incomplete=" + incomplete, () -> {
                var h = new Harness();
                h.local(UNESTABLISHED);
                h.discoveryIncomplete = incomplete;
                h.store.fault = FakeBootstrapStorage.Fault.CLEANUP;
                byte[][] installed = {null};
                h.store.beforeInstall = () -> {
                    assertEquals(PENDING, h.replay().establishment().phase());
                    assertEquals(1, h.replay().sequence());
                };
                h.memory.beforeAppend = () -> {
                    if (h.memory.appends == 1) {
                        assertEquals(2, h.store.reads); // absence preflight, then installed canonical
                        assertFalse(h.store.stagedClosed);
                        installed[0] = h.store.canonical.clone();
                        try (var canonical = new VaultUnlocker(KDF).unlock(installed[0], PASSWORD)) {
                            assertArrayEquals(ROOT, canonical.root());
                            assertArrayEquals(h.replay().establishment().binding().bytes(), canonical.binding());
                        }
                    }
                };
                try (var result = h.lifecycle().createNew(PASSWORD)) {
                    assertEquals(incomplete ? CREATED_ESTABLISHED_DISCOVERY_INCOMPLETE : CREATED_ESTABLISHED,
                            result.status());
                    assertEquals(ESTABLISHED, h.replay().establishment().phase());
                    assertEquals(2, h.replay().sequence());
                    assertEquals(1, h.memory.bytes[24]); // PENDING
                    assertEquals(2, h.memory.bytes[133]); // ESTABLISHED
                    assertTrue(h.store.stagedClosed);
                    assertNotNull(h.store.residue);
                    assertEquals(2, h.snapshots);
                    assertEquals(incomplete ? DiscoveryState.PROCESSING_INCOMPLETE : DiscoveryState.READY,
                            result.discovery().discoveryState());
                    var knowledge = result.discovery().knowledge();
                    assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN, knowledge.continuity());
                    assertFalse(knowledge.knowledgePersistenceBlocked());
                    assertTrue(knowledge.records().isEmpty());
                    assertTrue(result.discovery().readable().evidence().isEmpty());
                    var readiness = new VaultReadiness(knowledge, result.discovery().discoveryState());
                    assertTrue(readiness.baseOperationSafe());
                    assertTrue(readiness.candidateUseReady());
                    assertEquals(!incomplete, readiness.authoritativeVaultReady());
                }
                // Distinct hostile residue proves subsequent reads/open use only canonical bytes.
                h.store.residue = candidate(new byte[32]);
                assertArrayEquals(installed[0], VaultLifecycle.read(h.store.openCanonicalRead()));
                byte[] journal = h.memory.bytes.clone();
                try (var reopened = h.lifecycle().openConfigured(PASSWORD)) {
                    assertEquals(incomplete ? OPENED_ESTABLISHED_DISCOVERY_INCOMPLETE : OPENED_ESTABLISHED,
                            reopened.status());
                    assertArrayEquals(ROOT, reopened.root());
                }
                assertArrayEquals(journal, h.memory.bytes);
                assertArrayEquals(installed[0], h.store.canonical);
                assertArrayEquals(candidate(new byte[32]), h.store.residue);
                assertEquals(1, Collections.frequency(h.store.events, "install"));
                assertEquals(1, Collections.frequency(h.store.events, "staged-read"));
                assertEquals(1, Collections.frequency(h.store.events, "cleanup"));
                assertEquals(1, h.store.stages);
            }));
        }
        return tests;
    }

    @Test void cleanupFailureDoesNotMaskValidationOrPersistenceFailure() {
        for (boolean validationFailure : List.of(true, false)) {
            var h = new Harness(); h.store.fault = FakeBootstrapStorage.Fault.CLEANUP;
            if (validationFailure) { h.store.stagedSubstitution = candidate(new byte[32]); }
            else { h.memory.beforeAppend = () -> { if (h.memory.appends == 1) h.memory.failAppend = true; }; }
            h.failed(h.lifecycle().createNew(PASSWORD),
                    validationFailure ? PUBLICATION_INCOMPLETE : LOCAL_PERSISTENCE_FAILURE);
            assertEquals(PENDING, h.replay().establishment().phase());
            assertEquals(1, h.snapshots);
            assertTrue(h.store.stagedClosed);
            assertNotNull(h.store.residue);
            assertEquals(validationFailure ? 0 : 1, Collections.frequency(h.store.events, "install"));
        }
    }

    @Test void candidateConstructionAndSelfValidationFailBeforePending() {
        for (boolean writerFailure:List.of(true,false)) {
            var h=new Harness();
            Argon2idKdf bad=(p,s)-> {throw new IllegalStateException("Injected construction");};
            var lifecycle=new VaultLifecycle(h.store,h.memory,h.source,h.entropy,
                    new VaultBootstrapWriter(writerFailure?bad:KDF),new VaultUnlocker(writerFailure?KDF:(p,s)->new byte[32]));
            h.failed(lifecycle.createNew(PASSWORD),CRYPTO_CONSTRUCTION_FAILED);
            assertEquals(UNESTABLISHED,h.replay().establishment().phase());
            assertEquals(0,h.replay().sequence()); assertNull(h.store.canonical); assertEquals(0,h.store.stages);
            h.draws.forEach(b->assertArrayEquals(new byte[b.length],b));
        }
    }
    @Test void pendingPersistenceFailureDoesNotStage() {
        var h=new Harness(); h.memory.failAppend=true;
        h.failed(h.lifecycle().createNew(PASSWORD),LOCAL_PERSISTENCE_FAILURE);
        assertEquals(UNESTABLISHED,h.replay().establishment().phase()); assertEquals(0,h.store.stages); assertNull(h.store.canonical);
    }
    @Test void establishedPersistenceFailureCanRestartFromPublishedCanonical() {
        var h=new Harness(); h.memory.beforeAppend=()-> {if(h.memory.appends==1) h.memory.failAppend=true;};
        h.failed(h.lifecycle().createNew(PASSWORD),LOCAL_PERSISTENCE_FAILURE);
        assertNotNull(h.store.canonical); assertEquals(PENDING,h.replay().establishment().phase()); assertEquals(1,h.snapshots);
        h.memory.beforeAppend=()->{}; h.memory.failAppend=false;
        try(var result=h.lifecycle().openConfigured(PASSWORD)) {
            assertEquals(OPENED_ESTABLISHED,result.status()); assertEquals(2,h.replay().sequence());
        }
    }
    @Test void freshDiscoveryAfterCreationObservesSynchronizationRace() {
        var h=new Harness(); h.appearAfterPreflight=true;
        try(var result=h.lifecycle().createNew(PASSWORD)) {
            assertEquals(CREATED_ESTABLISHED,result.status()); assertEquals(1,h.contentReads);
            assertEquals(1,result.discovery().observations().size()); assertEquals(2,h.snapshots);
        }
    }
    @Test void incompletePostCreationDiscoveryPreservesEstablishment() {
        var h=new Harness(); h.discoveryIncomplete=true;
        try(var r=h.lifecycle().createNew(PASSWORD)) {
            assertEquals(CREATED_ESTABLISHED_DISCOVERY_INCOMPLETE,r.status()); assertNotNull(r.root());
            assertEquals(ESTABLISHED,h.replay().establishment().phase());
        }
    }
    @TestFactory List<DynamicTest> firstOpenMatrix() {
        var tests=new ArrayList<DynamicTest>();
        for(String mode:List.of("absent","unestablished","wrong-password","malformed","persist-fail","pending","established","canonical-absent")) {
            tests.add(DynamicTest.dynamicTest(mode,()-> {
                var h=new Harness(); h.store.canonical=candidate(ROOT);
                if(mode.equals("unestablished")) h.local(UNESTABLISHED);
                if(mode.equals("pending")) h.local(PENDING);
                if(mode.equals("established")) h.local(ESTABLISHED);
                if(mode.equals("malformed")) h.store.canonical=new byte[87];
                if(mode.equals("canonical-absent")) h.store.canonical=null;
                h.memory.failAppend=mode.equals("persist-fail");
                byte[] original=h.store.canonical==null?null:h.store.canonical.clone();
                var r=h.lifecycle().configureExisting(mode.equals("wrong-password")?new byte[0]:PASSWORD);
                switch(mode) {
                    case "wrong-password" -> h.failed(r,AUTHENTICATION_FAILED);
                    case "malformed" -> h.failed(r,INVALID_BOOTSTRAP);
                    case "persist-fail" -> h.failed(r,LOCAL_PERSISTENCE_FAILURE);
                    case "pending","established" -> h.failed(r,LOCAL_STATE_NOT_FRESH);
                    case "canonical-absent" -> h.failed(r,CANONICAL_VAULT_ABSENT);
                    default -> {
                        try(r) {assertEquals(OPENED_ESTABLISHED,r.status()); assertArrayEquals(ROOT,r.root());}
                        assertEquals(121,h.memory.bytes.length); assertEquals(1,h.replay().sequence());
                        assertEquals(2,h.memory.bytes[24]); assertEquals(1,h.snapshots);
                    }
                }
                if(List.of("wrong-password","malformed","canonical-absent").contains(mode)) assertNull(h.memory.bytes);
                if(!List.of("absent","unestablished").contains(mode)) assertEquals(0,h.snapshots);
                assertArrayEquals(original,h.store.canonical);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> configuredOpenMatrix() {
        var tests=new ArrayList<DynamicTest>();
        for(var phase:List.of(PENDING,ESTABLISHED)) for(String mode:List.of("match","absent","auth","different","persist-fail","incomplete")) {
            tests.add(DynamicTest.dynamicTest(phase+" "+mode,()-> {
                var h=new Harness(); h.local(phase); h.store.canonical=candidate(ROOT);
                if(mode.equals("absent")) h.store.canonical=null;
                if(mode.equals("auth")) h.store.canonical[86]^=1;
                if(mode.equals("different")) h.store.canonical=candidate(new byte[32]);
                h.memory.failAppend=mode.equals("persist-fail"); h.discoveryIncomplete=mode.equals("incomplete");
                byte[] before=h.memory.bytes.clone();
                var r=h.lifecycle().openConfigured(PASSWORD);
                switch(mode) {
                    case "absent" -> h.failed(r,phase==PENDING?PENDING_CANONICAL_ABSENT:CANONICAL_VAULT_ABSENT);
                    case "auth" -> h.failed(r,AUTHENTICATION_FAILED);
                    case "different" -> h.failed(r,phase==PENDING?PENDING_BINDING_MISMATCH:ESTABLISHED_BINDING_MISMATCH);
                    case "persist-fail" -> {
                        if(phase==PENDING) h.failed(r,LOCAL_PERSISTENCE_FAILURE);
                        else {try(r) {assertEquals(OPENED_ESTABLISHED,r.status());}}
                    }
                    default -> {try(r) {assertEquals(mode.equals("incomplete")?OPENED_ESTABLISHED_DISCOVERY_INCOMPLETE:OPENED_ESTABLISHED,r.status());}}
                }
                boolean success=List.of("match","incomplete").contains(mode) || mode.equals("persist-fail")&&phase==ESTABLISHED;
                assertEquals(success?1:0,h.snapshots);
                assertEquals(success?ESTABLISHED:phase,h.replay().establishment().phase());
                if(phase==ESTABLISHED || !success) assertArrayEquals(before,h.memory.bytes);
                else {assertEquals(2,h.replay().sequence()); assertEquals(before.length+109,h.memory.bytes.length);}
                assertTrue(h.draws.isEmpty()); assertEquals(0,h.store.stages);
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> missingCorruptUnsupportedAndTailNeverInitialize() {
        var tests=new ArrayList<DynamicTest>();
        for(String mode:List.of("absent","empty","corrupt","unsupported","tail")) for(String intent:List.of("create","configure","open")) {
            if(mode.equals("absent")&&!intent.equals("open")) continue;
            tests.add(DynamicTest.dynamicTest(intent+" "+mode,()-> {
                var h=new Harness(); h.store.canonical=candidate(ROOT);
                switch(mode) {
                    case "empty" -> h.memory.bytes=new byte[0];
                    case "corrupt" -> h.memory.bytes=new byte[12];
                    case "unsupported" -> {h.memory.bytes=SecurityMemoryJournal.header(); h.memory.bytes[11]=2;}
                    case "tail" -> {h.local(PENDING); h.memory.bytes=Arrays.copyOf(h.memory.bytes,h.memory.bytes.length+1);}
                }
                byte[] before=h.memory.bytes==null?null:h.memory.bytes.clone();
                var r=switch(intent) {
                    case "create" -> h.lifecycle().createNew(PASSWORD);
                    case "configure" -> h.lifecycle().configureExisting(PASSWORD);
                    default -> h.lifecycle().openConfigured(PASSWORD);
                };
                h.failed(r,mode.equals("absent")?LOCAL_SECURITY_MEMORY_MISSING:mode.equals("tail")?LOCAL_TAIL_REPAIR_REQUIRED:LOCAL_SECURITY_MEMORY_INVALID);
                assertArrayEquals(before,h.memory.bytes); assertEquals(0,h.store.reads); assertEquals(0,h.snapshots);
            }));
        }
        return tests;
    }
    @Test void readsAreBoundedAndAlwaysCloseIncludingIoFailure() throws Exception {
        for(int length:new int[]{0,86,87,88,1_000_000}) {
            int[] consumed={0}; boolean[] closed={false};
            var input=new InputStream() {
                @Override public int read() { return consumed[0]<length ? (++consumed[0] & 255) : -1; }
                @Override public void close() {closed[0]=true;}
            };
            assertEquals(Math.min(length,88),VaultLifecycle.read(input).length);
            assertEquals(Math.min(length,88),consumed[0]); assertTrue(closed[0]);
        }
        boolean[] closed={false};
        assertThrows(IOException.class,()->VaultLifecycle.read(new InputStream() {
            @Override public int read() throws IOException {throw new IOException("Injected");}
            @Override public void close(){closed[0]=true;}
        }));
        assertTrue(closed[0]); assertNull(VaultLifecycle.read(null));
    }
    @Test void fakeCopiesStagingAndKeepsItNoncanonical() throws Exception {
        var store=new FakeBootstrapStorage(); byte[] bytes=candidate(ROOT), saved=bytes.clone();
        try(var staged=store.stageInitial(bytes)) {
            bytes[0]^=1; assertNull(store.openCanonicalRead());
            assertArrayEquals(saved,VaultLifecycle.read(staged.openRead()));
            staged.installInitialDurably(); assertArrayEquals(saved,VaultLifecycle.read(store.openCanonicalRead()));
            assertThrows(IOException.class,staged::installInitialDurably);
        }
        store.close(); assertThrows(IOException.class,store::openCanonicalRead);
    }

    @Test void productionCreationAcceptsEmptyPassword() throws Exception {
        var store = new FakeBootstrapStorage();
        var memory = new MemoryJournalStorage();
        var lifecycle = new VaultLifecycle(store, memory, new DiscoveryFixtures());
        var entropyField = VaultLifecycle.class.getDeclaredField("entropy");
        entropyField.setAccessible(true);
        assertInstanceOf(EntropySource.Jdk.class, entropyField.get(lifecycle));
        try (var result = lifecycle.createNew(new byte[0]);
             var unlocked = new VaultUnlocker().unlock(store.canonical, new byte[0])) {
            assertEquals(CREATED_ESTABLISHED, result.status());
            assertArrayEquals(result.root(), unlocked.root());
        }
    }

    @Test void newlyArrivedValidObjectIsPersistedOnlyAfterEstablished() throws Exception {
        var f = DiscoveryFixtures.fixture(DiscoveryFixtures.TOKEN);
        var h = new Harness();
        int[] snapshots = {0};
        DiscoverySource source = () -> {
            if (++snapshots[0] == 1) {
                return new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.NONE);
            }
            assertEquals(ESTABLISHED, h.replay().establishment().phase());
            assertEquals(2, h.replay().sequence());
            var real = new DiscoveryFixtures(); real.put(f); return real.snapshot();
        };
        EntropySource entropy = b -> { if (b.length == 32) System.arraycopy(f.root(), 0, b, 0, 32); };
        h.memory.beforeAppend = () -> {
            if (h.memory.appends == 2) assertEquals(ESTABLISHED, h.replay().establishment().phase());
        };
        var lifecycle = new VaultLifecycle(h.store, h.memory, source, entropy,
                new VaultBootstrapWriter(KDF), new VaultUnlocker(KDF));
        try (var result = lifecycle.createNew(PASSWORD)) {
            assertEquals(CREATED_ESTABLISHED, result.status());
            assertEquals(1, result.discovery().knowledge().size());
            assertEquals(3, h.replay().sequence());
            assertEquals(SecurityMemoryJournal.TOKEN, h.memory.bytes[242]);
        }
        byte[] before = h.memory.bytes.clone();
        h.store.canonical = null;
        h.failed(h.lifecycle().openConfigured(PASSWORD), CANONICAL_VAULT_ABSENT);
        assertArrayEquals(before, h.memory.bytes);
        assertEquals(1, h.replay().knowledge().size());
    }

    @Test void preflightResourceFailuresBlockWithoutEntropyOrInitialization() {
        for (boolean closeFailure : List.of(true, false)) {
            var h = new Harness();
            DiscoverySource source = () -> {
                if (!closeFailure) throw new IOException("Enumeration failed");
                return new DiscoverySource.Snapshot(List.of(), DiscoverySource.SnapshotIssue.NONE,
                        () -> { throw new IOException("Close failed"); });
            };
            var lifecycle = new VaultLifecycle(h.store, h.memory, source, h.entropy,
                    new VaultBootstrapWriter(KDF), new VaultUnlocker(KDF));
            h.failed(lifecycle.createNew(PASSWORD), CREATE_BLOCKED_DISCOVERY_INCOMPLETE);
            assertTrue(h.draws.isEmpty()); assertNull(h.memory.bytes);
        }
    }

    @Test void canonicalIoFailureIsNotAuthenticationOrAbsence() {
        var h = new Harness();
        VaultBootstrapStorage unavailable = new VaultBootstrapStorage() {
            @Override public InputStream openCanonicalRead() throws IOException {
                throw new IOException("Unavailable");
            }
            @Override public StagedBootstrap stageInitial(byte[] bytes) { throw new AssertionError(); }
            @Override public void close() {}
        };
        var lifecycle = new VaultLifecycle(unavailable, h.memory, h.source);
        h.failed(lifecycle.configureExisting(PASSWORD), BOOTSTRAP_STORAGE_UNAVAILABLE);
        h.failed(lifecycle.createNew(PASSWORD), BOOTSTRAP_STORAGE_UNAVAILABLE);
        assertNull(h.memory.bytes); assertEquals(0, h.snapshots);
    }

    @Test void absentAndUnestablishedConfiguredOpenNeverInitialize() throws Exception {
        var h = new Harness(); h.store.canonical = candidate(ROOT);
        h.failed(h.lifecycle().openConfigured(PASSWORD), LOCAL_SECURITY_MEMORY_MISSING);
        h.local(UNESTABLISHED); byte[] before = h.memory.bytes.clone();
        h.failed(h.lifecycle().openConfigured(PASSWORD), LOCAL_STATE_NOT_FRESH);
        assertArrayEquals(before, h.memory.bytes); assertEquals(0, h.store.reads);
    }

    @Test void partialEstablishmentAppendRequiresExplicitRepairOnRestart() {
        var h = new Harness();
        h.memory.beforeAppend = () -> { if (h.memory.appends == 1) h.memory.partial = 57; };
        h.failed(h.lifecycle().createNew(PASSWORD), LOCAL_PERSISTENCE_FAILURE);
        assertNotNull(h.store.canonical);
        assertEquals(SecurityMemoryJournal.Status.INCOMPLETE_TAIL, h.replay().status());
        byte[] before = h.memory.bytes.clone();
        h.failed(h.lifecycle().openConfigured(PASSWORD), LOCAL_TAIL_REPAIR_REQUIRED);
        assertArrayEquals(before, h.memory.bytes);
    }

    @Test void malformedStreamLengthsNeverInitializeLocalState() {
        for (int size : new int[]{0, 86, 88, 1_000_000}) {
            var h = new Harness(); h.store.canonical = Arrays.copyOf(candidate(ROOT), size);
            h.failed(h.lifecycle().configureExisting(PASSWORD), INVALID_BOOTSTRAP);
            assertNull(h.memory.bytes); assertEquals(0, h.snapshots);
        }
    }

    @Test void ambiguousCompleteAppendsUseActualReplayStateOnRestart() {
        for (boolean failPending : List.of(true, false)) {
            var h = new Harness();
            h.memory.beforeAppend = () -> {
                if (h.memory.appends == (failPending ? 0 : 1)) h.memory.partial = 109;
            };
            h.failed(h.lifecycle().createNew(PASSWORD), LOCAL_PERSISTENCE_FAILURE);
            assertEquals(failPending ? PENDING : ESTABLISHED, h.replay().establishment().phase());
            assertEquals(SecurityMemoryJournal.Status.CLEAN, h.replay().status());
            h.memory.beforeAppend = () -> {}; h.memory.partial = -1;
            byte[] before = h.memory.bytes.clone();
            if (failPending) {
                assertEquals(0, h.store.stages);
                h.failed(h.lifecycle().openConfigured(PASSWORD), PENDING_CANONICAL_ABSENT);
            } else {
                try (var result = h.lifecycle().openConfigured(PASSWORD)) {
                    assertEquals(OPENED_ESTABLISHED, result.status());
                }
            }
            assertArrayEquals(before, h.memory.bytes);
        }
    }

    @Test void initializationFailureNeverPublishesOrScans() {
        var h = new Harness(); h.store.canonical = candidate(ROOT);
        SecurityMemoryStorage unavailable = new SecurityMemoryStorage() {
            @Override public InputStream openRead() { return null; }
            @Override public void initializeDurably(byte[] header) throws IOException { throw new IOException("Injected"); }
            @Override public void appendDurably(byte[] bytes) { throw new AssertionError(); }
            @Override public void truncateDurably(long offset) { throw new AssertionError(); }
            @Override public void close() {}
        };
        var lifecycle = new VaultLifecycle(h.store, unavailable, h.source, h.entropy,
                new VaultBootstrapWriter(KDF), new VaultUnlocker(KDF));
        h.failed(lifecycle.configureExisting(PASSWORD), LOCAL_PERSISTENCE_FAILURE);
        assertEquals(0, h.snapshots);
        h.store.canonical = null;
        h.failed(lifecycle.createNew(PASSWORD), LOCAL_PERSISTENCE_FAILURE);
        assertTrue(h.draws.isEmpty()); assertEquals(0, h.store.stages);
    }
}
