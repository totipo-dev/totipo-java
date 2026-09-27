package dev.totipo.format;

import static dev.totipo.format.SecurityMemoryJournal.*;
import static dev.totipo.format.DiscoveryFixtures.fixture;
import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.DynamicTest;

class SecurityMemoryJournalTest {
    static SecurityBytes field(int n) { byte[] b = new byte[32]; b[31] = (byte)n; return new SecurityBytes(b, 32); }
    static ObjectId id(int n) { return new ObjectId(field(n).bytes()); }
    static KnownTokenNode token(int n, int version, List<ObjectId> parents, BigInteger time) {
        return new KnownTokenNode(id(n), version, version == 1 ? SemanticStatus.SUPPORTED_VALID : SemanticStatus.OPAQUE_ROUTABLE,
                field(50), parents, field(60), time);
    }
    static KnownTokenNode token(int n) { return token(n, 1, List.of(), BigInteger.ZERO); }
    static KnownDeviceNode device(int n, int version) {
        return new KnownDeviceNode(id(n), version, version == 1 ? SemanticStatus.SUPPORTED_VALID : SemanticStatus.OPAQUE_ROUTABLE,
                field(51), List.of(id(2), id(3)), new BigInteger("ffffffffffffffff",16),
                version == 1 ? new SecurityBytes(new byte[65],65) : null);
    }
    static OpaqueUnscopedRecord opaque(int n) {
        byte[] b = new byte[1024]; for (int i = 0; i < b.length; i++) { b[i] = (byte)i; }
        return new OpaqueUnscopedRecord(id(n), new SecurityBytes(b,1024));
    }
    static SecurityMemorySession established(MemoryJournalStorage store) throws IOException {
        var s = SecurityMemorySession.initializeNew(store); assertTrue(s.establishFirstOpen(field(42).bytes())); return s;
    }
    static Replay replay(byte[] b) throws IOException { return SecurityMemoryJournal.replay(new ByteArrayInputStream(b)); }
    static void appendRaw(MemoryJournalStorage store, int type, byte[] payload) throws IOException {
        var r = replay(store.bytes); store.appendDurably(frame(r.sequence()+1, r.digest(), type, payload));
    }
    static void unknown(DurableKnowledgeState state) {
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN, state.continuity());
    }

    @Test void exactHeaderAbsentEmptyAndUnsupported() throws Exception {
        assertEquals("544f5449504f2d534d000001", HexFormat.of().formatHex(header()));
        assertEquals(Status.ABSENT, SecurityMemoryJournal.replay(null).status());
        assertEquals(Status.CORRUPT, replay(new byte[0]).status());
        assertEquals(Status.CLEAN, replay(header()).status());
        for (int i=0;i<header().length;i++) {
            assertEquals(Status.CORRUPT, replay(Arrays.copyOf(header(),i)).status());
            byte[] b=header(); b[i]^=1;
            assertEquals(i < 10 ? Status.CORRUPT : Status.UNSUPPORTED_LOCAL_FORMAT, replay(b).status());
        }
        var storage = new MemoryJournalStorage(); storage.bytes = new byte[0];
        assertThrows(IOException.class, () -> SecurityMemorySession.initializeNew(storage));
    }
    @Test void establishmentLifecycleAndImmutableBinding() throws Exception {
        var store = new MemoryJournalStorage(); var s = SecurityMemorySession.initializeNew(store);
        assertEquals(LocalEstablishment.Phase.UNESTABLISHED,s.establishment().phase());
        assertThrows(IllegalStateException.class, () -> s.commitRecord(token(1)));
        assertThrows(IllegalArgumentException.class, () -> s.establishFromPending(field(42).bytes()));
        assertTrue(s.persistPending(field(42).bytes())); int length=store.bytes.length;
        assertTrue(s.persistPending(field(42).bytes())); assertEquals(length,store.bytes.length);
        var pending=SecurityMemorySession.open(store);
        assertEquals(LocalEstablishment.Phase.PENDING,pending.establishment().phase());
        assertArrayEquals(field(42).bytes(),pending.establishment().binding().bytes());
        assertThrows(IllegalArgumentException.class, () -> pending.establishFromPending(field(43).bytes()));
        assertThrows(IllegalArgumentException.class, () -> pending.establishFirstOpen(field(42).bytes()));
        assertTrue(pending.establishFromPending(field(42).bytes()));
        assertTrue(pending.establishFromPending(field(42).bytes()));
        assertThrows(IllegalArgumentException.class, () -> pending.establishFirstOpen(field(43).bytes()));
        assertThrows(IllegalArgumentException.class, () -> pending.persistPending(field(42).bytes()));
        assertEquals(LocalEstablishment.Phase.ESTABLISHED,SecurityMemorySession.open(store).establishment().phase());
    }
    @Test void failedEstablishmentDoesNotChangeState() throws Exception {
        var store = new MemoryJournalStorage(); var s=SecurityMemorySession.initializeNew(store); store.failAppend=true;
        assertFalse(s.persistPending(field(42).bytes()));
        assertEquals(LocalEstablishment.Phase.UNESTABLISHED,s.establishment().phase());
        store.failAppend=false;
        assertFalse(s.establishFirstOpen(field(42).bytes())); // ambiguous write poisons this session
    }
    @Test void realBootstrapBindingPendingRestartAndEstablished() throws Exception {
        var v=VectorCaseLoader.bootstrapCases().get(0); var b=v.data().field("bootstrap");
        var unlocked=new VaultUnlocker().unlock(b.field("record_hex").hex(),b.field("password_hex").hex());
        var store=new MemoryJournalStorage(); var s=SecurityMemorySession.initializeNew(store);
        assertTrue(s.persistPending(unlocked.binding())); s=SecurityMemorySession.open(store);
        assertArrayEquals(b.field("binding_hex").hex(),s.establishment().binding().bytes());
        // Canonical bootstrap publication/authentication success is modeled externally.
        assertTrue(s.establishFromPending(unlocked.binding()));
        assertArrayEquals(unlocked.binding(),SecurityMemorySession.open(store).establishment().binding().bytes());
    }
    @Test void allRecordKindsRoundTripAndIdempotence() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store);
        var records=List.of(token(1), token(2,2,List.of(id(1),id(3)),new BigInteger("ffffffffffffffff",16)),
                device(4,1),device(5,2),opaque(6));
        for (var r:records) {
            assertEquals(DurableKnowledgeState.Outcome.INSERTED,s.commitRecord(r).outcome());
            var head=s.head(); int length=store.bytes.length;
            assertEquals(DurableKnowledgeState.Outcome.UNCHANGED,s.commitRecord(r).outcome());
            assertSame(head,s.head()); assertEquals(length,store.bytes.length);
        }
        var replay=replay(store.bytes); assertEquals(Status.CLEAN,replay.status());
        for(var r:records) { assertEquals(r,replay.knowledge().record(r.objectId())); }
        assertArrayEquals(opaque(6).exactObjectBytes().bytes(),((OpaqueUnscopedRecord)replay.knowledge().record(id(6))).exactObjectBytes().bytes());
        appendRaw(store,TOKEN,encode(token(1))); assertEquals(5,replay(store.bytes).knowledge().size());
    }
    @Test void markerSurvivesAndAllowsAdditionalEvidence() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store);
        assertTrue(s.markUnknown()); long sequence=s.head().sequence(); assertTrue(s.markUnknown());
        assertEquals(sequence,s.head().sequence());
        s.commitRecord(token(1)); unknown(s.knowledge());
        var reopened=SecurityMemorySession.open(store); unknown(reopened.knowledge()); assertEquals(1,reopened.knowledge().size());
        assertFalse(reopened.head().corruptionForcedUnknown()); // explicit marker, not replay corruption
        reopened.commitRecord(token(2)); unknown(replay(store.bytes).knowledge()); assertEquals(2,replay(store.bytes).knowledge().size());
    }
    @Test void conflictAndCrossKindNeverOverwriteAndPersistMarker() throws Exception {
        for(var conflicting:List.of(token(1,2,List.of(),BigInteger.ONE),device(1,1),opaque(1))) {
            var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(token(1));
            int length=store.bytes.length; s.commitRecord(conflicting); unknown(s.knowledge());
            assertEquals(length+MIN_FRAME,store.bytes.length);
            assertEquals(token(1),s.knowledge().record(id(1))); unknown(replay(store.bytes).knowledge());
        }
        for(var conflicting:List.of(device(1,2),token(1),opaque(1))) {
            var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(device(1,1));
            int length=store.bytes.length;
            assertEquals(DurableKnowledgeState.Outcome.LOCAL_CONTINUITY_UNKNOWN,s.commitRecord(conflicting).outcome());
            unknown(s.knowledge()); assertEquals(length+MIN_FRAME,store.bytes.length);
            assertEquals(device(1,1),s.knowledge().record(id(1))); unknown(replay(store.bytes).knowledge());
        }
    }
    @Test void scopedProposalRequiresReclassificationWithoutDegradingKnownContinuity() throws Exception {
        assertDeferredReclassification(false);
    }
    @Test void scopedProposalRequiresReclassificationWithoutAnotherUnknownMarker() throws Exception {
        assertDeferredReclassification(true);
    }
    private static void assertDeferredReclassification(boolean alreadyUnknown) throws Exception {
        for(String fixtureId:List.of(DiscoveryFixtures.TOKEN,"v1.crypto.device-root.001")) {
            var f=fixture(fixtureId);
            var scoped=new ObjectDiscovery().classify(f.id(),f.bytes(),f.root()).authenticated();
            assertNotNull(scoped);
            var store=new MemoryJournalStorage(); var s=established(store);
            if(alreadyUnknown) { assertTrue(s.markUnknown()); }
            // Trusted prior-classification seam, as in the existing discovery regression.
            // The proposed scoped observation goes through actual authentication/validation.
            var retained=new OpaqueUnscopedRecord(f.id(),new SecurityBytes(f.bytes(),1024));
            s.commitRecord(retained);
            var knowledge=s.knowledge(); var head=s.head(); byte[] bytes=store.bytes.clone();
            int appends=store.appends;
            store.beforeAppend=()->fail("Reclassification must not attempt a storage append");

            var result=s.commit(scoped);

            assertEquals(DurableKnowledgeState.Outcome.RECLASSIFICATION_REQUIRED,result.outcome());
            assertSame(knowledge,result.state()); assertSame(knowledge,s.knowledge());
            assertEquals(alreadyUnknown ? LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN
                    : LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN,s.knowledge().continuity());
            assertFalse(s.knowledge().knowledgePersistenceBlocked());
            assertSame(retained,s.knowledge().record(f.id())); assertEquals(1,s.knowledge().size());
            assertArrayEquals(f.bytes(),((OpaqueUnscopedRecord)s.knowledge().record(f.id())).exactObjectBytes().bytes());
            assertSame(head,s.head()); assertEquals(head.sequence(),s.head().sequence());
            assertEquals(head.digest(),s.head().digest()); assertEquals(head.verifiedBytes(),s.head().verifiedBytes());
            assertArrayEquals(bytes,store.bytes); assertEquals(appends,store.appends);
            assertEquals(retained,replay(store.bytes).knowledge().record(f.id()));
        }
    }
    @Test void sessionDiscoveryDefersReclassificationWithoutAdmittingReadableEvidence() throws Exception {
        var f=fixture(DiscoveryFixtures.TOKEN); var source=new DiscoveryFixtures(); source.put(f);
        var store=new MemoryJournalStorage(); var s=established(store);
        var retained=new OpaqueUnscopedRecord(f.id(),new SecurityBytes(f.bytes(),1024));
        s.commitRecord(retained);
        var knowledge=s.knowledge(); var head=s.head(); byte[] bytes=store.bytes.clone();
        int appends=store.appends;
        store.beforeAppend=()->fail("Discovery must not append a deferred scoped interpretation");

        var result=DiscoveryCoordinator.discover(source,f.root(),s);

        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE,result.discoveryState());
        assertTrue(result.resourceComplete());
        assertSame(knowledge,result.knowledge()); assertSame(knowledge,s.knowledge());
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN,result.knowledge().continuity());
        assertFalse(result.knowledge().knowledgePersistenceBlocked());
        assertSame(retained,result.knowledge().record(f.id())); assertEquals(1,result.knowledge().size());
        assertArrayEquals(f.bytes(),((OpaqueUnscopedRecord)result.knowledge().record(f.id())).exactObjectBytes().bytes());
        assertNotNull(result.observations().get(0).readable()); // diagnostic observation is still available
        assertTrue(result.readable().evidence().isEmpty());
        assertFalse(new VaultReadiness(result.knowledge(),result.discoveryState()).authoritativeVaultReady());
        assertSame(head,s.head()); assertEquals(head.sequence(),s.head().sequence());
        assertEquals(head.digest(),s.head().digest()); assertEquals(head.verifiedBytes(),s.head().verifiedBytes());
        assertArrayEquals(bytes,store.bytes); assertEquals(appends,store.appends);
    }
    @Test void markerFailureBlocksProcessButCannotPromiseRestartMemory() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(token(1)); store.failAppend=true;
        s.commitRecord(device(1,1)); unknown(s.knowledge()); assertTrue(s.knowledge().knowledgePersistenceBlocked());
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_KNOWN,replay(store.bytes).knowledge().continuity());
    }
    @Test void frameBeforeAuthoritativeStateAndFailurePoisonsFurtherWrites() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store);
        store.beforeAppend=()->assertNull(s.knowledge().record(id(1)));
        s.commitRecord(token(1)); store.beforeAppend=()->{};
        store.failAppend=true; assertEquals(DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED,s.commitRecord(token(2)).outcome());
        assertNull(s.knowledge().record(id(2))); assertNull(replay(store.bytes).knowledge().record(id(2)));
        store.failAppend=false; s.commitRecord(token(3)); assertNull(s.knowledge().record(id(3)));
    }
    @Test void replayConflictAndCycleRetainRecords() throws Exception {
        var store=new MemoryJournalStorage(); established(store);
        var a=token(1,1,List.of(id(2)),BigInteger.ZERO); var b=token(2,1,List.of(id(1)),BigInteger.ONE);
        appendRaw(store,TOKEN,encode(a)); appendRaw(store,TOKEN,encode(b));
        var r=replay(store.bytes); unknown(r.knowledge()); assertEquals(2,r.knowledge().size());
        assertTrue(r.corruptionForcedUnknown());
        assertEquals(GraphIntegrityStatus.RESOLVED_CYCLE,new GraphTopology(r.knowledge()).integrity());
        appendRaw(store,DEVICE,encode(device(1,1))); r=replay(store.bytes); unknown(r.knowledge()); assertEquals(a,r.knowledge().record(id(1)));
    }
    @TestFactory List<DynamicTest> completeFirstAndLaterFrameMutations() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); int second=store.bytes.length; s.commitRecord(opaque(6));
        var tests=new ArrayList<DynamicTest>();
        for(int start:new int[]{12,second}) for(int relative:new int[]{0,3,4,11,12,13,44,45,76,
                (start == 12 ? second : store.bytes.length)-start-1}) {
            final int at=start+relative;
            tests.add(DynamicTest.dynamicTest("mutate offset "+at,()->{
                byte[] b=store.bytes.clone(); b[at]^=1; var r=replay(b);
                assertNotEquals(Status.CLEAN,r.status());
                assertNotEquals(Status.INCOMPLETE_TAIL,r.status());
                unknown(r.knowledge());
            }));
        }
        return tests;
    }
    @TestFactory List<DynamicTest> everyFinalTruncationPointPreservesPriorHead() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(token(1));
        int prefix=store.bytes.length; var head=s.head(); s.commitRecord(opaque(6));
        var tests=new ArrayList<DynamicTest>();
        for(int i=prefix+1;i<store.bytes.length;i++) { final int cut=i;
            tests.add(DynamicTest.dynamicTest("cut "+i,()->{
                var r=replay(Arrays.copyOf(store.bytes,cut)); assertEquals(Status.INCOMPLETE_TAIL,r.status());
                assertEquals(prefix,r.verifiedBytes()); assertEquals(head.sequence(),r.sequence()); assertEquals(head.digest(),r.digest());
                assertEquals(1,r.knowledge().size()); assertNull(r.knowledge().record(id(6))); assertTrue(r.repairRequired());
            }));
        }
        return tests;
    }
    @Test void malformedMiddleAndDamagedCompleteFrameAreNotTail() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); int prefix=store.bytes.length; s.commitRecord(token(1));
        byte[] last=Arrays.copyOfRange(store.bytes,prefix,store.bytes.length);
        store.bytes=Arrays.copyOf(store.bytes,prefix+55); store.appendDurably(last);
        assertEquals(Status.CORRUPT,replay(store.bytes).status());
        store.bytes[prefix]=127; assertEquals(Status.CORRUPT,replay(store.bytes).status());
    }
    @Test void limitsSequencesUnknownTypesAndImpossiblePayloads() throws Exception {
        for(int size:new int[]{0,76,MAX_FRAME+1,Integer.MAX_VALUE,-1,Integer.MIN_VALUE}) {
            var b=ByteBuffer.allocate(16).put(header()).putInt(size).array(); assertEquals(Status.CORRUPT,replay(b).status());
        }
        assertEquals(MAX_FRAME,frame(1,new SecurityBytes(hash(header()),32),UNKNOWN,new byte[MAX_FRAME-MIN_FRAME]).length);
        assertThrows(IllegalArgumentException.class,()->frame(1,field(0),UNKNOWN,new byte[MAX_FRAME-MIN_FRAME+1]));
        var store=new MemoryJournalStorage(); var s=established(store);
        for(long sequence:new long[]{0,1,3,Long.MAX_VALUE}) {
            byte[] bad=ByteBuffer.allocate(4+8+1+32).putInt(MIN_FRAME).putLong(sequence).put((byte)UNKNOWN).put(s.head().digest().bytes()).array();
            byte[] domain="totipo-java/security-memory/frame/v1\0".getBytes(StandardCharsets.US_ASCII);
            byte[] digest=hash(CryptoSupport.join(domain,header(),bad));
            assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,bad,digest)).status());
        }
        byte[] future=frame(2,s.head().digest(),127,new byte[0]);
        assertEquals(Status.UNSUPPORTED_LOCAL_FORMAT,replay(CryptoSupport.join(store.bytes,future)).status());
        for(var payload:List.of(new byte[0],new byte[31],new byte[33])) {
            assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,frame(2,s.head().digest(),PENDING,payload))).status());
        }
        byte[] d=encode(device(4,1)); d[32]=2; d[33]=2; // future node illegally retaining a key
        assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,frame(2,s.head().digest(),DEVICE,d))).status());
        d=encode(device(4,2)); d[32]=1; d[33]=1; // supported node missing key
        assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,frame(2,s.head().digest(),DEVICE,d))).status());
    }
    @Test void invalidTransitionsAndGraphBeforeEstablishmentFailClosed() throws Exception {
        var store=new MemoryJournalStorage(); SecurityMemorySession.initializeNew(store);
        appendRaw(store,TOKEN,encode(token(1))); assertEquals(Status.CORRUPT,replay(store.bytes).status());
        store=new MemoryJournalStorage(); var s=established(store);
        appendRaw(store,ESTABLISHED,field(43).bytes()); assertEquals(Status.CORRUPT,replay(store.bytes).status());
        assertEquals(field(42),replay(store.bytes).establishment().binding());
    }
    @Test void partialAppendRestartRepairAndCompleteOlderCorruption() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(token(1)); s.commitRecord(device(2,1));
        long verified=s.head().verifiedBytes(); store.partial=57; s.commitRecord(opaque(3));
        var r=replay(store.bytes); assertEquals(Status.INCOMPLETE_TAIL,r.status()); assertEquals(2,r.knowledge().size());
        var reopened=SecurityMemorySession.open(store); store.partial=-1;
        assertFalse(new VaultReadiness(reopened.knowledge(),DiscoveryState.READY).baseOperationSafe());
        assertEquals(DurableKnowledgeState.Outcome.PERSISTENCE_BLOCKED,reopened.commitRecord(token(4)).outcome());
        store.truncateDurably(verified); assertEquals(Status.CLEAN,replay(store.bytes).status());
        SecurityMemorySession.open(store).commitRecord(token(4)); assertEquals(3,replay(store.bytes).knowledge().size());
        store.bytes[60]^=1; r=replay(store.bytes); assertEquals(Status.CORRUPT,r.status()); unknown(r.knowledge()); assertEquals(0,r.knowledge().size());
    }
    @Test void discoveryJournalReplayAndFailedAppend() throws Exception {
        var f=fixture(DiscoveryFixtures.TOKEN); var source=new DiscoveryFixtures(); source.put(f);
        var store=new MemoryJournalStorage(); var s=established(store);
        var result=DiscoveryCoordinator.discover(source,f.root(),s);
        assertSame(s.knowledge(),result.knowledge()); assertEquals(DiscoveryState.READY,result.discoveryState());
        assertEquals(1,result.readable().evidence().size());
        var reopened=SecurityMemorySession.open(store); assertEquals(result.knowledge().records(),reopened.knowledge().records());
        var absent=DiscoveryCoordinator.discover(new DiscoveryFixtures(),f.root(),reopened);
        assertTrue(absent.readable().evidence().isEmpty()); assertEquals(1,absent.knowledge().size());
        var again=DiscoveryCoordinator.discover(source,f.root(),reopened);
        assertEquals(result.readable().evidence().iterator().next().value(),again.readable().evidence().iterator().next().value());
        var node=(KnownTokenNode)reopened.knowledge().record(f.id());
        assertEquals(Set.of(f.id()),again.topology().currentTokenHeads(node.tokenId()));
        assertEquals(new VaultReadiness(result.knowledge(),result.discoveryState()).authoritativeVaultReady(),
                new VaultReadiness(again.knowledge(),again.discoveryState()).authoritativeVaultReady());
        var failStore=new MemoryJournalStorage(); var fail=established(failStore); failStore.failAppend=true;
        var failed=DiscoveryCoordinator.discover(source,f.root(),fail);
        assertEquals(DiscoveryState.PROCESSING_INCOMPLETE,failed.discoveryState());
        assertTrue(failed.knowledge().knowledgePersistenceBlocked()); assertEquals(0,failed.knowledge().size());
        assertEquals(0,replay(failStore.bytes).knowledge().size());
    }
    @Test void realOpaqueBytesAndSecretMinimization() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store);
        var f=fixture("v1.routing.unknown-type-unscoped.001");
        var observation=new ObjectDiscovery().classify(f.id(),f.bytes(),f.root());
        s.commit(observation.authenticated());
        assertArrayEquals(f.bytes(),((OpaqueUnscopedRecord)replay(store.bytes).knowledge().record(f.id())).exactObjectBytes().bytes());
        var tokenFixture=fixture(DiscoveryFixtures.TOKEN);
        var tokenObservation=new ObjectDiscovery().classify(tokenFixture.id(),tokenFixture.bytes(),tokenFixture.root());
        var cleanStore=new MemoryJournalStorage(); var clean=established(cleanStore); clean.commit(tokenObservation.authenticated());
        // Minimum node encoding is exactly 108 bytes for a root, independent of all TOKEN value material.
        assertEquals(108,encode(tokenObservation.authenticated().record()).length);
        assertFalse(contains(cleanStore.bytes,tokenFixture.bytes()));
        assertFalse(contains(cleanStore.bytes,tokenFixture.root()));
        byte[] secret="DISTINCTIVE_SECRET_56789".getBytes(StandardCharsets.US_ASCII);
        var value=TokenValueFixtures.value(1,"Distinctive issuer 123456","Distinctive account abcxyz",1,6,30,secret);
        var readable=TokenValueFixtures.readable(17,value);
        clean.commitRecord(readable.routing());
        byte[] deviceSemantic=TlvTestBytes.replace(ProvenanceTest.device().semanticBytes(),0x0202,
                "Distinctive DEVICE name".getBytes(StandardCharsets.UTF_8));
        var deviceAssertion=ProvenanceTest.valid(deviceSemantic,ProvenanceTest.root(ProvenanceTest.device()));
        clean.commit(AuthenticatedObservation.supported(deviceAssertion));
        for(String text:List.of(value.issuer(),value.account(),"Distinctive DEVICE name")) {
            assertFalse(contains(cleanStore.bytes,text.getBytes(StandardCharsets.UTF_8)));
        }
        assertFalse(contains(cleanStore.bytes,secret));
        assertFalse(clean.head().toString().contains(HexFormat.of().formatHex(field(42).bytes())));
        assertFalse(clean.establishment().toString().contains(HexFormat.of().formatHex(field(42).bytes())));
    }
    @Test void provenanceIsRecomputedAndValuesAreNotReplayed() throws Exception {
        var fixture=ProvenanceTest.token(); var root=ProvenanceTest.root(fixture);
        var assertion=ProvenanceTest.valid(fixture.semanticBytes(),root);
        var store=new MemoryJournalStorage(); var s=established(store);
        s.commit(AuthenticatedObservation.supported(assertion)); byte[] before=store.bytes.clone();
        var r=replay(before); var graph=new GraphTopology(r.knowledge());
        assertTrue(new CurrentReadableValues(graph,List.of()).evidence().isEmpty());
        assertEquals(ProvenanceStatus.UNRESOLVED,ProvenanceTest.evaluate(assertion,root));
        assertEquals(ProvenanceStatus.VERIFIED,ProvenanceTest.evaluate(assertion,root,ProvenanceTest.key(fixture)));
        assertArrayEquals(before,store.bytes);
    }
    @Test void authenticatedInvalidKnownObservationPersistsIndependentMarker() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store); s.commitRecord(token(1));
        long sequence=s.head().sequence(); s.authenticatedInvalidSemantic(id(2)); assertEquals(sequence,s.head().sequence());
        s.authenticatedInvalidSemantic(id(1)); assertEquals(sequence+1,s.head().sequence());
        assertEquals(token(1),replay(store.bytes).knowledge().record(id(1))); unknown(replay(store.bytes).knowledge());
    }
    @Test void replayUsesBoundedReadsAndCanonicalPayloads() throws Exception {
        var store=new MemoryJournalStorage(); var s=established(store);
        for(int i=1;i<=100;i++) s.commitRecord(token(i));
        var input=new FilterInputStream(new ByteArrayInputStream(store.bytes)) {
            @Override public byte[] readAllBytes() { throw new AssertionError("Whole journal read"); }
            @Override public byte[] readNBytes(int len) throws IOException {
                assertTrue(len<=MAX_FRAME); return super.readNBytes(len);
            }
            @Override public int read(byte[] bytes,int offset,int length) throws IOException {
                return super.read(bytes,offset,Math.min(7,length));
            }
        };
        assertEquals(100,SecurityMemoryJournal.replay(input).knowledge().size());
        var parents=new ArrayList<ObjectId>(); for(int i=1;i<=32;i++) parents.add(id(i));
        var max=token(200,2,parents,BigInteger.ZERO);
        s.commitRecord(max); assertEquals(max,replay(store.bytes).knowledge().record(id(200)));
        for(int offset:new int[]{33,66,67}) {
            byte[] bad=encode(token(201)); bad[offset]=(byte)255;
            assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,frame(s.head().sequence()+1,s.head().digest(),TOKEN,bad))).status());
        }
        byte[] wrongPrev=frame(s.head().sequence()+1,field(123),UNKNOWN,new byte[0]);
        assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,wrongPrev)).status());
        byte[] huge=frame(s.head().sequence()+1,s.head().digest(),UNKNOWN,new byte[MAX_FRAME-MIN_FRAME]);
        assertEquals(Status.CORRUPT,replay(CryptoSupport.join(store.bytes,huge)).status());
    }
    @Test void confirmationAndPresentationHaveNoFormatTagsAndDiagnosticsAreStructural() {
        // Confirmation execution is not implemented in core yet. Pin the complete v1 tag set;
        // process-local confirmation/context/presentation state has no encoding or replay path.
        assertEquals(List.of(1,2,3,4,5,6),List.of(PENDING,ESTABLISHED,UNKNOWN,TOKEN,DEVICE,UNSCOPED));
        assertEquals("KnownTokenNode[version=1, status=SUPPORTED_VALID, parents=0]",token(1).toString());
        assertEquals("KnownDeviceNode[version=1, status=SUPPORTED_VALID, parents=2]",device(2,1).toString());
        assertEquals("OpaqueUnscopedRecord[1024 bytes retained]",opaque(3).toString());
    }
    static boolean contains(byte[] haystack,byte[] needle) {
        outer:for(int i=0;i<=haystack.length-needle.length;i++) { for(int j=0;j<needle.length;j++) if(haystack[i+j]!=needle[j]) continue outer; return true; } return false;
    }
    @Test void goldenPrivateFormat() throws Exception {
        var store=new MemoryJournalStorage(); var s=SecurityMemorySession.initializeNew(store);
        s.persistPending(field(42).bytes()); assertEquals(121,store.bytes.length);
        s.establishFromPending(field(42).bytes()); assertEquals(230,store.bytes.length);
        s.commitRecord(token(1)); assertEquals(415,store.bytes.length);
        s.commitRecord(device(4,1)); assertEquals(698,store.bytes.length);
        s.commitRecord(opaque(6)); assertEquals(1831,store.bytes.length);
        s.markUnknown(); assertEquals(1908,store.bytes.length);
        assertEquals("2c9aa5d6390c244e1ab324bbf958589046bb0f766616ea0829fff33be499067a",HexFormat.of().formatHex(hash(store.bytes)));
    }
}
