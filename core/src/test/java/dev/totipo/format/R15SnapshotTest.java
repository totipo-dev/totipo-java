package dev.totipo.format;

import java.math.BigInteger;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;

class R15SnapshotTest {
    static final byte[] ROOT=DeviceWriterTest.root();
    static SnapshotSession session(){return new SnapshotSession(new SecurityBytes(VaultLifecycleTest.binding(ROOT),32));}
    static TokenUpdatePublication.Context context(SnapshotSession session){return new TokenUpdatePublication.Context(new InitialDeviceAdvertisement.Context(session));}
    static AcceptedToken token(int n,TokenValue value,ObjectId... parents)throws Exception{return TokenValueFixtures.readable(n,value,parents);}
    static TokenValue value(String account){return TokenValueFixtures.value(1,"Example",account,1,6,30,(byte)1);}
    @Test void relevantAndUnrelatedConfirmationChanges() throws Exception {
        var a=token(1,value("a"));var b=token(2,value("b"));var base=GraphTopologyTest.state(a,b);var target=a.tokenId();
        for(String change:List.of("other-token","device","diagnostic","provenance","heads","alternatives","desired","intent","learn-disappear")){
            var session=session();session.replace(base);var desired=value("chosen");
            try(var identity=new DeviceWriterTest.CapturingKey().identity()){
                var prepared=TokenResolutionConfirmation.prepare(ROOT,context(session),identity,target,desired,TokenUpdatePublication.Intent.ORDINARY);
                assertEquals(CONFIRMATION_PREPARED,prepared.status());var consent=prepared.confirmation();
                switch(change){
                    case "other-token" -> session.accept(GraphTopologyTest.node(true,500,501,1));
                    case "device" -> session.accept(GraphTopologyTest.node(false,500,501,1));
                    case "diagnostic" -> session.replace(new AcceptedSnapshot(base.objects(),true));
                    case "provenance" -> session.accept(new AcceptedDevice(GraphTopologyTest.id(500),1,SemanticStatus.SUPPORTED_VALID,
                            a.authorDeviceId(),List.of(),BigInteger.ZERO,new SecurityBytes(DeviceWriterTest.KEY,65)));
                    case "heads" -> session.accept(token(3,value("new"),a.objectId()));
                    case "alternatives" -> {
                        var map=new HashMap<>(base.objects());map.put(a.objectId(),new AcceptedToken(a.objectId(),1,a.semanticStatus(),a.tokenId(),a.parents(),a.authorDeviceId(),a.authorTime(),value("changed")));
                        session.replace(new AcceptedSnapshot(map,false));
                    }
                    case "desired" -> desired=value("other choice");
                    case "learn-disappear" -> {session.accept(token(3,value("new"),a.objectId()));session.replace(base);}
                    default -> {}
                }
                var intent=change.equals("intent")?TokenUpdatePublication.Intent.RESTORE:TokenUpdatePublication.Intent.ORDINARY;
                assertEquals(Set.of("other-token","device","diagnostic","provenance").contains(change),consent.fresh(context(session),target,desired,intent),change);
            }
        }
    }
    @Test void confirmationNeverDropsWideFrontier() throws Exception {
        var session=session();
        for(int n=1;n<=33;n++)session.accept(token(n,value(n%2==0?"a":"b")));
        try(var identity=new DeviceWriterTest.CapturingKey().identity()){
            var chosen=value("chosen");var token=TokenValueFixtures.TOKEN;
            var consent=TokenResolutionConfirmation.prepare(ROOT,context(session),identity,token,chosen,TokenUpdatePublication.Intent.ORDINARY);
            var store=new FakeV1ObjectPublicationStore();
            var result=TokenUpdatePublication.publishConfirmed(ROOT,()->context(session),identity,token,chosen,new byte[8],TokenUpdatePublication.Intent.ORDINARY,consent.confirmation(),store,List.of());
            assertEquals(FOLD_REQUIRED,result.status());assertEquals(0,store.calls);assertEquals(33,session.snapshot().topology().currentTokenHeads(token).size());
        }
    }
    @Test void discoveryIncompleteAndUnscopedAreCurrentDiagnosticsOnly() throws Exception {
        var a=DiscoveryFixtures.fixture(DiscoveryFixtures.TOKEN);var source=new DiscoveryFixtures();source.put(a);
        source.entries.put("objects-v1/"+"a".repeat(64),new DiscoveryFixtures.Entry("regular",null));
        var pass=DiscoveryCoordinator.discover(source,a.root());
        assertFalse(pass.resourceComplete());assertEquals(1,pass.snapshot().objects().size());
        var accepted=(AcceptedToken)pass.snapshot().object(a.id());
        assertTrue(new TokenOperationPolicy(pass.snapshot(),accepted.tokenId()).ordinaryUse().eligible());
        var session=new SnapshotSession(new SecurityBytes(VaultLifecycleTest.binding(a.root()),32));session.replace(pass.snapshot());
        try(var identity=new DeviceWriterTest.CapturingKey().identity()){
            assertEquals(PUBLISHED_DEVICE_REQUIRED,TokenUpdatePublication.publish(a.root(),()->context(session),identity,accepted.tokenId(),accepted.value(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,new FakeV1ObjectPublicationStore(),List.of()).status());
        }
        var unscoped=DiscoveryFixtures.fixture("v1.routing.unknown-type-unscoped.001");source.entries.clear();source.put(a);source.put(unscoped);
        pass=DiscoveryCoordinator.discover(source,a.root());assertTrue(pass.snapshot().hasUnscopedEvidence());
        assertTrue(new TokenOperationPolicy(pass.snapshot(),accepted.tokenId()).ordinaryUse().eligible());
        source.remove(unscoped.id());pass=DiscoveryCoordinator.discover(source,a.root());assertFalse(pass.snapshot().hasUnscopedEvidence());
        assertEquals(1,pass.snapshot().objects().size());
    }
    @Test void remoteProvenanceReevaluatesOnDeviceArrivalAndDisappearance() throws Exception {
        var t=ProvenanceTest.token();var d=ProvenanceTest.device();byte[] root=ProvenanceTest.root(t);
        var token=ProvenanceTest.valid(t.semanticBytes(),root);var device=ProvenanceTest.valid(d.semanticBytes(),root);
        var snapshot=GraphTopologyTest.state(AuthenticatedObservation.supported(token).record());
        assertEquals(ProvenanceStatus.UNRESOLVED,ProvenanceEvaluator.evaluate(token,root,snapshot.verificationKeys()));
        var withDevice=snapshot.accepting(AuthenticatedObservation.supported(device).record());
        assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(token,root,withDevice.verificationKeys()));
        assertEquals(ProvenanceStatus.UNRESOLVED,ProvenanceEvaluator.evaluate(token,root,snapshot.verificationKeys()));
        assertEquals(snapshot.topology().currentTokenHeads(((AcceptedToken)snapshot.object(token.objectId())).tokenId()),
                withDevice.topology().currentTokenHeads(((AcceptedToken)snapshot.object(token.objectId())).tokenId()));
    }
    @Test void ordinaryPlanningIgnoresLaterDiagnosticsAndDeviceArrival() throws Exception {
        var session=session();var a=token(1,value("a"));session.accept(a);
        try(var identity=new DeviceWriterTest.CapturingKey().identity()){
            var store=new FakeV1ObjectPublicationStore();
            var result=TokenUpdatePublication.publish(ROOT,()->context(session),identity,a.tokenId(),value("edit"),new byte[8],TokenUpdatePublication.Intent.ORDINARY,store,List.of(),()->{
                session.accept(GraphTopologyTest.node(false,500,501,1));session.accept(GraphTopologyTest.node(true,501,502,1));
                session.replace(new AcceptedSnapshot(session.snapshot().objects(),true));
            });
            assertEquals(PUBLISHED_DEVICE_REQUIRED,result.status());assertEquals(1,store.calls);
            assertEquals(List.of(a.objectId()),((AcceptedToken)session.snapshot().object(result.receipt().objectId())).parents());
        }
    }
}
