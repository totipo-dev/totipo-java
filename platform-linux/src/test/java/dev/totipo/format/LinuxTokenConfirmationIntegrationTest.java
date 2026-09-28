package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import static dev.totipo.format.TokenUpdatePublication.Intent.*;
import static dev.totipo.format.LinuxTokenUpdateIntegrationTest.*;

class LinuxTokenConfirmationIntegrationTest {
    @org.junit.jupiter.api.io.TempDir(factory=LocalStorageTempDirectory.class) Path dir;

    @ParameterizedTest @ValueSource(booleans={false,true})
    void ambiguousPublicationRequiresRealReconciliation(boolean installed) throws Exception {
        var setup=new LinuxTokenUpdateIntegrationTest();setup.dir=dir;setup.establish();
        var sync=setup.sync;var local=setup.local;
        try(var memory=LinuxSecurityMemoryStorage.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                var initial=LinuxTokenPublicationIntegrationTest.token(session,identity,store,List.of());
                var token=initial.receipt().tokenId();var heads=new HashSet<ObjectId>();
                for(int i=0;i<2;i++) {
                    var semantic=TokenWriter.signed(ROOT,identity,token.bytes(),value(1,"branch"+i,"",i+1),new byte[8],List.of(initial.receipt().objectId()));
                    var object=V1EnvelopeWriter.seal(ROOT,semantic);store.publishDurably(object.id(),object.bytes());heads.add(object.id());
                }
                DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session);
                var desired=value(1,"chosen","",9);
                var c=TokenResolutionConfirmation.prepare(ROOT,context(session,sync,Set.of()),identity,token,desired,ORDINARY).confirmation();
                int[] calls={0};ObjectId[] attempted={null};
                var ambiguous=new V1ObjectPublicationStore() {
                    public PublicationResult publishDurably(ObjectId id,byte[] bytes) throws java.io.IOException {
                        calls[0]++;attempted[0]=id;
                        if(installed)store.publishDurably(id,bytes);
                        throw new java.io.IOException("Injected ambiguous acknowledgement");
                    }
                    public void close() {}
                };
                assertEquals(PUBLICATION_INCOMPLETE,TokenUpdatePublication.publishConfirmed(ROOT,()->context(session,sync,Set.of()),identity,
                        token,desired,new byte[8],ORDINARY,c,ambiguous,List.of()).status());
                assertNull(session.knowledge().record(attempted[0]));
                var second=TokenResolutionConfirmation.prepare(ROOT,context(session,sync,Set.of()),identity,token,desired,ORDINARY);
                assertEquals(RECONCILIATION_REQUIRED,second.status());assertNull(second.confirmation());
                assertEquals(RECONCILIATION_REQUIRED,update(session,sync,identity,token,desired,ORDINARY,ambiguous,List.of(),Set.of()).status());
                assertEquals(1,calls[0]);
                var result=session.tokenPublicationFence().reconcile(new NioDiscoverySource(sync),ROOT,session);
                assertEquals(DiscoveryState.READY,result.discoveryState());assertFalse(session.tokenPublicationFence().reconciliationRequired());
                assertEquals(installed?Set.of(attempted[0]):heads,result.topology().currentTokenHeads(token));
                assertEquals(CONFIRMATION_STALE,TokenUpdatePublication.publishConfirmed(ROOT,()->context(session,sync,Set.of()),identity,
                        token,desired,new byte[8],ORDINARY,c,ambiguous,List.of()).status());
                var next=TokenResolutionConfirmation.prepare(ROOT,context(session,sync,Set.of()),identity,token,desired,ORDINARY);
                assertEquals(installed?CONFIRMATION_NOT_REQUIRED:CONFIRMATION_PREPARED,next.status());
                assertEquals(1,calls[0]);
            }
        }
    }

    @ParameterizedTest @ValueSource(strings={"conflict","unavailable","graphFailure","crash"})
    void confirmedResolutionSurvivesRestart(String mode) throws Exception {
        var setup=new LinuxTokenUpdateIntegrationTest();setup.dir=dir;setup.establish();
        var sync=setup.sync;var local=setup.local;var missing=new HashSet<ObjectId>();
        var heads=new HashSet<ObjectId>();SecurityBytes token;ObjectId finalId=null;
        var desired=value(1,"chosen third","account",99);var faults=new StorageFaults();
        TokenResolutionConfirmation oldConfirmation;
        try(var memory=faults.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                var device=LinuxObjectPublicationIntegrationTest.publish(session,identity,DiscoveryState.READY,store);
                var ads=List.of(LinuxTokenPublicationIntegrationTest.ad(sync,device.objectId()));
                var initial=LinuxTokenPublicationIntegrationTest.token(session,identity,store,ads);
                token=initial.receipt().tokenId();
                for(int i=0;i<2;i++) {
                    var bytes=TokenWriter.signed(ROOT,identity,token.bytes(),value(1,"branch"+i,"",i+1),new byte[8],List.of(initial.receipt().objectId()));
                    var object=V1EnvelopeWriter.seal(ROOT,bytes);store.publishDurably(object.id(),object.bytes());heads.add(object.id());
                }
                assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
                if(mode.equals("unavailable")) {
                    var id=heads.iterator().next();Files.delete(sync.resolve("objects-v1").resolve(id.filename()));missing.add(id);
                    assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
                }
                var before=Files.readAllBytes(local.resolve("security-memory-v1.bin"));
                var preparation=TokenResolutionConfirmation.prepare(ROOT,context(session,sync,missing),identity,token,desired,ORDINARY);
                assertEquals(CONFIRMATION_PREPARED,preparation.status());oldConfirmation=preparation.confirmation();
                assertEquals(heads,preparation.current().currentHeadIds());assertEquals(missing,preparation.current().unavailableSupportedHeadIds());
                assertArrayEquals(before,Files.readAllBytes(local.resolve("security-memory-v1.bin")));
                if(mode.equals("graphFailure"))faults.failWrite=true;
                if(!mode.equals("crash")) {
                    var r=TokenUpdatePublication.publishConfirmed(ROOT,()->context(session,sync,missing),identity,token,desired,new byte[8],ORDINARY,
                            oldConfirmation,store,ads);
                    assertEquals(mode.equals("graphFailure")?KNOWLEDGE_PERSISTENCE_FAILED:PUBLISHED_AND_REMEMBERED_SUCCESS_READY,r.status());
                    if(r.receipt()!=null)finalId=r.receipt().objectId();
                    if(mode.equals("graphFailure")) {
                        assertEquals(heads,new GraphTopology(session.knowledge()).currentTokenHeads(token));
                        assertTrue(session.knowledge().knowledgePersistenceBlocked());
                    }
                }
            }
        }
        if(mode.equals("crash")) {
            var paths=new ArrayList<String>();
            for(Class<?> type:List.of(TokenPublicationCrashProcess.class,LinuxDurability.class,NioV1ObjectPublicationStore.class,ObjectId.class))
                paths.add(Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString());
            var process=new ProcessBuilder(Path.of(System.getProperty("java.home"),"bin/java").toString(),
                    "--enable-native-access=ALL-UNNAMED","--illegal-native-access=deny","-cp",String.join(java.io.File.pathSeparator,paths),
                    TokenPublicationCrashProcess.class.getName(),"confirmed",sync.toString(),local.toString()).redirectErrorStream(true).start();
            try {
                assertTrue(process.waitFor(30,java.util.concurrent.TimeUnit.SECONDS));
                var output=new String(process.getInputStream().readAllBytes(),java.nio.charset.StandardCharsets.UTF_8).trim();
                assertEquals(0,process.exitValue(),output);finalId=ObjectId.fromFilename(output);
            }finally{process.destroyForcibly();}
        }
        try(var memory=LinuxSecurityMemoryStorage.open(local);var keys=LinuxDeviceProvenanceKeyStore.open(local);
            var store=NioV1ObjectPublicationStore.open(sync,LinuxDurability.open())) {
            var session=SecurityMemorySession.open(memory);
            if(mode.equals("crash"))assertNull(session.knowledge().record(finalId));
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(new NioDiscoverySource(sync),ROOT,session).discoveryState());
            var c=context(session,sync,missing);var current=c.graph().currentTokenHeads(token);assertEquals(1,current.size());
            if(finalId!=null)assertEquals(Set.of(finalId),current);
            var id=current.iterator().next();var n=(KnownTokenNode)session.knowledge().record(id);
            assertEquals(DeviceWriter.canonicalParents(heads),n.parents());heads.forEach(p->assertTrue(c.graph().ancestor(p,id)));
            var view=CurrentTokenValueEvaluator.evaluate(c.graph(),token,c.readable());assertEquals(CurrentTokenValueState.SEMANTICALLY_UNAMBIGUOUS,view.state());
            if(!mode.equals("crash"))assertEquals(Set.of(desired),view.distinctReadableValues());
            assertTrue(view.unavailableSupportedHeadIds().isEmpty());
            for(var absent:missing) {assertNotNull(session.knowledge().record(absent));assertFalse(Files.exists(sync.resolve("objects-v1").resolve(absent.filename())));}
            try(var identity=DeviceIdentityLifecycle.loadExisting(session.head(),keys)) {
                assertEquals(CONFIRMATION_STALE,TokenUpdatePublication.publishConfirmed(ROOT,()->context(session,sync,missing),identity,token,desired,
                        new byte[8],ORDINARY,oldConfirmation,store,List.of()).status());
            }
        }
    }
}
