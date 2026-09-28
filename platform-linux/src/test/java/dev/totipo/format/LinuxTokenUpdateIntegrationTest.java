package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import static dev.totipo.format.TokenUpdatePublication.Intent.*;

class LinuxTokenUpdateIntegrationTest {
    @org.junit.jupiter.api.io.TempDir(factory = LocalStorageTempDirectory.class) Path dir;
    Path sync, local;
    void establish() throws Exception {
        var setup=new LinuxObjectPublicationIntegrationTest();setup.dir=dir;setup.establish();sync=setup.sync;local=setup.local;
    }
    static TokenUpdatePublication.Context context(SecurityMemorySession session, Path sync, Set<ObjectId> unavailable) {
        var g=new GraphTopology(session.knowledge());var values=new ArrayList<ReadableTokenValue>();
        for(var record:session.knowledge().records().values()) {
            if(record instanceof KnownTokenNode n && n.semanticStatus()==SemanticStatus.SUPPORTED_VALID && !unavailable.contains(n.objectId())) {
                try {
                    var bytes=Files.readAllBytes(sync.resolve("objects-v1").resolve(n.objectId().filename()));
                    values.add(ReadableTokenValue.supported(AssertionValidator.validate(EnvelopeReader.open(n.objectId().filename(),bytes,ROOT)).object()));
                }catch(java.io.IOException e){throw new java.io.UncheckedIOException(e);}
            }
        }
        return new TokenUpdatePublication.Context(new InitialDeviceAdvertisement.Context(session,DiscoveryState.READY,0),g,new CurrentReadableValues(g,values));
    }
    static TokenValue value(int status,String issuer,String account,int secret) {
        return new TokenValue(status,issuer,account,new TokenValue.Credential(1,6,30,new SecurityBytes(new byte[]{(byte)secret},1)));
    }
    static InitialTokenPublication.Result update(SecurityMemorySession session,Path sync,DeviceIdentityResult identity,
            SecurityBytes token,TokenValue desired,TokenUpdatePublication.Intent intent,V1ObjectPublicationStore store,
            List<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> ads,Set<ObjectId> unavailable) {
        return TokenUpdatePublication.publish(ROOT,()->context(session,sync,unavailable),identity,token,desired,new byte[8],intent,store,ads);
    }
    @Test void lifecycleSurvivesRestartWithImmutableHistory() throws Exception {
        establish();var originals=new HashMap<ObjectId,byte[]>();SecurityBytes token;ObjectId finalId;
        var desired=value(1,"edited issuer","edited account",77);
        try(var memory=LinuxSecurityMemoryStorage.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                var device=LinuxObjectPublicationIntegrationTest.publish(session,identity,DiscoveryState.READY,store);
                var ads=List.of(LinuxTokenPublicationIntegrationTest.ad(sync,device.objectId()));
                var initial=LinuxTokenPublicationIntegrationTest.token(session,identity,store,ads);
                token=initial.receipt().tokenId();var previous=initial.receipt().objectId();
                originals.put(previous,Files.readAllBytes(sync.resolve("objects-v1").resolve(previous.filename())));
                var edits=List.of(value(1,"edited issuer","edited account",1),desired,value(2,"edited issuer","edited account",77),desired);
                for(int i=0;i<edits.size();i++) {
                    var result=update(session,sync,identity,token,edits.get(i),i==3?RESTORE:ORDINARY,store,ads,Set.of());
                    assertEquals(PUBLISHED_AND_REMEMBERED_SUCCESS_READY,result.status());
                    var id=result.receipt().objectId();var n=(KnownTokenNode)session.knowledge().record(id);
                    assertEquals(List.of(previous),n.parents());
                    var c=context(session,sync,Set.of());
                    var policy=new TokenOperationPolicy(new VaultReadiness(session.knowledge(),DiscoveryState.READY),c.graph(),token,c.readable());
                    assertEquals(Set.of(id),c.graph().currentTokenHeads(token));
                    assertEquals(Set.of(edits.get(i)),policy.current().distinctReadableValues());
                    assertEquals(i!=2,policy.ordinaryUse().eligible());
                    originals.put(id,Files.readAllBytes(sync.resolve("objects-v1").resolve(id.filename())));previous=id;
                }
                finalId=previous;
            }
        }
        try(var memory=LinuxSecurityMemoryStorage.open(local)) {
            var session=SecurityMemorySession.open(memory);
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
            var c=context(session,sync,Set.of());assertEquals(Set.of(finalId),c.graph().currentTokenHeads(token));
            assertEquals(Set.of(desired),CurrentTokenValueEvaluator.evaluate(c.graph(),token,c.readable()).distinctReadableValues());
            for(var entry:originals.entrySet()) assertArrayEquals(entry.getValue(),Files.readAllBytes(sync.resolve("objects-v1").resolve(entry.getKey().filename())));
        }
    }
    @ParameterizedTest @ValueSource(strings={"equal","conflict","unavailable"})
    void concurrentDiscoveryAndNegativePaths(String mode) throws Exception {
        establish();
        try(var memory=LinuxSecurityMemoryStorage.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                var initial=LinuxTokenPublicationIntegrationTest.token(session,identity,store,List.of());
                var token=initial.receipt().tokenId();var a=initial.receipt().objectId();var children=new HashSet<ObjectId>();
                for(int i=0;i<2;i++) {
                    var semantic=TokenWriter.signed(ROOT,identity,token.bytes(),value(1,"same",mode.equals("conflict")?"branch"+i:"same",1),
                            java.nio.ByteBuffer.allocate(8).putLong(i).array(),List.of(a));
                    var object=V1EnvelopeWriter.seal(ROOT,semantic);store.publishDurably(object.id(),object.bytes());children.add(object.id());
                }
                assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
                assertEquals(children,new GraphTopology(session.knowledge()).currentTokenHeads(token));
                long journal=Files.size(local.resolve("security-memory-v1.bin"));
                long files;try(var list=Files.list(sync.resolve("objects-v1"))){files=list.count();}
                var result=update(session,sync,identity,token,value(1,"same","same",1),ORDINARY,store,List.of(),mode.equals("unavailable")?Set.of(children.iterator().next()):Set.of());
                if(mode.equals("equal")) {
                    assertEquals(PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED,result.status());
                    assertEquals(DeviceWriter.canonicalParents(children),((KnownTokenNode)session.knowledge().record(result.receipt().objectId())).parents());
                    assertEquals(Set.of(result.receipt().objectId()),new GraphTopology(session.knowledge()).currentTokenHeads(token));
                }else {
                    assertEquals(mode.equals("conflict")?CONFIRMATION_REQUIRED_CONFLICT:CONFIRMATION_REQUIRED_UNAVAILABLE,result.status());
                    assertEquals(journal,Files.size(local.resolve("security-memory-v1.bin")));
                    try(var list=Files.list(sync.resolve("objects-v1"))){assertEquals(files,list.count());}
                }
            }
        }
    }
    @Test void graphFailureLeavesUpdateForDiscovery() throws Exception {
        establish();var faults=new StorageFaults();SecurityBytes token;ObjectId a;
        try(var memory=faults.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                var initial=LinuxTokenPublicationIntegrationTest.token(session,identity,store,List.of());token=initial.receipt().tokenId();a=initial.receipt().objectId();
                faults.failWrite=true;
                assertEquals(KNOWLEDGE_PERSISTENCE_FAILED,update(session,sync,identity,token,value(1,"new","",2),ORDINARY,store,List.of(),Set.of()).status());
                assertTrue(session.knowledge().knowledgePersistenceBlocked());assertEquals(Set.of(a),new GraphTopology(session.knowledge()).currentTokenHeads(token));
            }
        }
        try(var memory=LinuxSecurityMemoryStorage.open(local)) {
            var session=SecurityMemorySession.open(memory);
            assertEquals(Set.of(a),new GraphTopology(session.knowledge()).currentTokenHeads(token));
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
            var g=new GraphTopology(session.knowledge());var heads=g.currentTokenHeads(token);assertEquals(1,heads.size());
            assertTrue(g.ancestor(a,heads.iterator().next()));
            var c=context(session,sync,Set.of());
            assertEquals(Set.of(value(1,"new","",2)),CurrentTokenValueEvaluator.evaluate(c.graph(),token,c.readable()).distinctReadableValues());
        }
    }
}
