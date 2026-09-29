package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import java.math.BigInteger;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DevicePresentationUpdate.Status.*;

class DevicePresentationUpdateTest {
    static final byte[] ROOT = DeviceWriterTest.root();
    static final SecurityBytes DEVICE = new SecurityBytes(P256.deviceId(DeviceWriterTest.KEY),32);
    static SnapshotSession session() { return new SnapshotSession(new SecurityBytes(VaultLifecycleTest.binding(ROOT),32)); }
    static AcceptedDevice node(int id, String name, ProvenanceStatus provenance, ObjectId... parents) {
        return new AcceptedDevice(GraphTopologyTest.id(id),1,SemanticStatus.SUPPORTED_VALID,DEVICE,
                DeviceWriter.canonicalParents(List.of(parents)),BigInteger.ZERO,new SecurityBytes(DeviceWriterTest.KEY,65),name,provenance);
    }
    static AcceptedDevice read(ObjectId id, byte[] bytes) {
        var opened=EnvelopeReader.open(id.filename(),bytes,ROOT);
        assertEquals(EnvelopeReader.Status.AUTHENTICATED_V1_STRUCTURE,opened.status());
        var assertion=AssertionValidator.validate(opened);
        assertEquals(AssertionValidator.Status.ASSERTION_VALID,assertion.status());
        var provenance=ProvenanceEvaluator.evaluate(assertion.object(),ROOT,VerificationKeyMaterial.keys());
        assertEquals(ProvenanceStatus.VERIFIED,provenance);
        var device=(AcceptedDevice)AuthenticatedObservation.supported(assertion.object(),provenance).record();
        assertEquals(DEVICE,device.deviceId());assertArrayEquals(DeviceWriterTest.KEY,device.publicKeyX963().bytes());
        return device;
    }
    static AcceptedDevice update(SnapshotSession session, DeviceIdentityResult identity, String name) {
        var heads=session.snapshot().topology().currentDeviceHeads(DEVICE);
        var store=new FakeV1ObjectPublicationStore();
        var result=DevicePresentationUpdate.publish(ROOT,session,identity,name,new byte[8],store);
        assertEquals(PUBLISHED,result.status());assertEquals(1,store.calls);
        var read=read(result.objectId(),store.get(result.objectId()));
        assertEquals(heads,Set.copyOf(read.parents()));assertEquals(name,read.displayName());
        assertEquals(read,session.snapshot().object(result.objectId()));return read;
    }
    @Test void sequentialNamesAndSingletonReaffirmationKeepIdentity() {
        var s=session();var a=node(1,"phone",ProvenanceStatus.VERIFIED);s.accept(a);
        var key=new DeviceWriterTest.CapturingKey();
        try(var identity=key.identity()) {
            var b=update(s,identity,"daily phone");var c=update(s,identity,"main phone");
            var d=update(s,identity,"main phone");
            assertEquals(List.of(a.objectId()),b.parents());assertEquals(List.of(b.objectId()),c.parents());
            assertEquals(List.of(c.objectId()),d.parents());assertEquals(3,key.calls);
            assertEquals(Set.of("main phone"),DevicePresentation.evaluate(s.snapshot(),DEVICE).names());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void equalOrConflictingNamesConvergeWithEveryInertHead(boolean equal) {
        var s=session();var a=node(1,"old",ProvenanceStatus.VERIFIED);s.accept(a);
        s.accept(node(2,"phone",ProvenanceStatus.VERIFIED,a.objectId()));
        s.accept(node(3,equal?"phone":"pixel",ProvenanceStatus.VERIFIED,a.objectId()));
        s.accept(node(4,"hostile",ProvenanceStatus.REJECTED,a.objectId()));
        s.accept(node(5,"unknown",ProvenanceStatus.UNRESOLVED,a.objectId()));
        var presentation=DevicePresentation.evaluate(s.snapshot(),DEVICE);
        assertEquals(equal?DevicePresentation.State.VERIFIED:DevicePresentation.State.CONFLICTED,presentation.state());
        assertEquals(Set.of(GraphTopologyTest.id(4),GraphTopologyTest.id(5)),presentation.inertHeads());
        var key=new DeviceWriterTest.CapturingKey();
        try(var identity=key.identity()) {
            var d=update(s,identity,equal?"phone":"main phone");assertEquals(4,d.parents().size());
            assertEquals(Set.of(d.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));assertEquals(1,key.calls);
        }
    }
    @Test void futureVectorBlocksRenameButLeavesTokenStateAndGenerationUsable() throws Exception {
        var fixture=VectorCaseLoader.futureCases().stream().filter(c->c.id().equals("v1.future.device-presentation.001")).findFirst().orElseThrow();
        var runner=new R15SnapshotVectorTest.Runner(fixture.data().field("graph").field("steps").array());
        runner.run();var s=runner.session;var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        var before=s.snapshot();
        try(var identity=key.identity()) {
            assertEquals(OPAQUE_DEVICE_HEAD,DevicePresentationUpdate.publish(ROOT,s,identity,"new",new byte[8],store).status());
        }
        assertSame(before,s.snapshot());assertEquals(0,key.calls);assertEquals(0,store.calls);
        var token=(AcceptedToken)before.objects().values().stream().filter(AcceptedToken.class::isInstance).findFirst().orElseThrow();
        assertTrue(new TokenOperationPolicy(before,token.tokenId()).ordinaryUse().eligible());
        var c=token.value().credential();
        var code=Totp.generate(new V1Plaintext.Credential(c.algorithm(),c.digits(),c.period(),c.secret().bytes()),59);
        // A supported descendant from a client understanding future semantics restores presentation.
        var opaque=before.topology().currentDeviceHeads(DEVICE).iterator().next();
        s.accept(node(500,"readable",ProvenanceStatus.VERIFIED,opaque));
        assertEquals(Set.of("readable"),DevicePresentation.evaluate(s.snapshot(),DEVICE).names());
        try(var identity=key.identity()){update(s,identity,"restored");}
        assertEquals(token,s.snapshot().object(token.objectId()));
        var after=((AcceptedToken)s.snapshot().object(token.objectId())).value().credential();
        assertEquals(code,Totp.generate(new V1Plaintext.Credential(after.algorithm(),after.digits(),after.period(),after.secret().bytes()),59));
    }
    @Test void pinnedCapacityDecidesBeforeSigning() throws Exception {
        for(var fixture:VectorCaseLoader.cases("size")) {
            if(!Set.of("v1.size.device-max-14.001","v1.size.device-max-15-fold.001","v1.size.short-der-no-extra-parent.001").contains(fixture.id()))continue;
            var input=fixture.data().field("input");var s=session();
            for(var parent:input.field("parents").array()) {
                var id=new ObjectId(Base64.getDecoder().decode(parent.string()));
                s.accept(new AcceptedDevice(id,1,SemanticStatus.SUPPORTED_VALID,DEVICE,List.of(),BigInteger.ZERO,
                        new SecurityBytes(DeviceWriterTest.KEY,65),"old",ProvenanceStatus.VERIFIED));
            }
            var heads=s.snapshot().topology().currentDeviceHeads(DEVICE);var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
            try(var identity=key.identity()) {
                var result=DevicePresentationUpdate.publish(ROOT,s,identity,input.field("display_name").string(),new byte[8],store);
                boolean fits=fixture.data().field("size").field("fits").bool();
                assertEquals(PUBLISHED,result.status());assertEquals(fits?1:2,key.calls);assertEquals(fits?1:2,store.calls);
                if(fits)assertEquals(heads,Set.copyOf(read(result.objectId(),store.get(result.objectId())).parents()));
                else DeviceFoldTest.verify(store,result.objectId(),heads,input.field("display_name").string(),new byte[8]);
            }
        }
    }
    @ParameterizedTest @ValueSource(strings={"", "a", "é", "éé", "\u0000\u001b", "e\u0301"})
    void nameAndU64AreExact(String name) {
        var s=session();s.accept(node(1,"old",ProvenanceStatus.VERIFIED));
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        byte[] time=HexFormat.of().parseHex("ffffffffffffffff");
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,name,time,store,()->Arrays.fill(time,(byte)0));
            var d=read(result.objectId(),store.get(result.objectId()));assertEquals(name,d.displayName());
            assertEquals(new BigInteger("18446744073709551615"),d.authorTime());assertEquals(1,key.calls);
        }
    }
    @Test void preSigningFailuresAndNoArbitraryIdentity() {
        var s=session();var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            s.accept(GraphTopologyTest.node(false,900,901,1));
            assertEquals(NO_EXISTING_DEVICE,DevicePresentationUpdate.publish(ROOT,s,identity,"name",new byte[8],store).status());
            s.accept(node(1,"old",ProvenanceStatus.VERIFIED));
            for(String invalid:List.of("x".repeat(257),"é".repeat(129),"\ud800","\udc00"))
                assertEquals(INVALID_DISPLAY_NAME,DevicePresentationUpdate.publish(ROOT,s,identity,invalid,new byte[8],store).status());
            assertEquals(DEVICE_IDENTITY_UNAVAILABLE,DevicePresentationUpdate.publish(ROOT,s,null,"name",new byte[8],store).status());
            assertEquals(DEVICE_IDENTITY_BINDING_MISMATCH,DevicePresentationUpdate.publish(ROOT,new SnapshotSession(new SecurityBytes(new byte[32],32)),identity,"name",new byte[8],store).status());
        }
        assertEquals(0,key.calls);assertEquals(0,store.calls);
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void lateBranchBeforeOrAfterPublicationIsOrdinaryConcurrency(boolean before) {
        var s=session();var a=node(1,"old",ProvenanceStatus.VERIFIED);s.accept(a);
        var remote=node(2,"remote",ProvenanceStatus.VERIFIED,a.objectId());
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,"local",new byte[8],store,()->{
                if(before)s.accept(remote);
                s.accept(GraphTopologyTest.node(false,99,99,1));s.accept(GraphTopologyTest.node(true,98,98,1));
                s.accept(new OpaqueUnscopedRecord(GraphTopologyTest.id(97)));
                s.replace(new AcceptedSnapshot(s.snapshot().objects(),true));
            });
            assertEquals(PUBLISHED,result.status());if(!before)s.accept(remote);
            assertEquals(List.of(a.objectId()),read(result.objectId(),store.get(result.objectId())).parents());
            assertEquals(Set.of(remote.objectId(),result.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
            assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
        }
    }
    @Test void publicationAmbiguityDoesNotAcceptOrFenceAndExactExistingAcknowledges() throws Exception {
        for(var fault:List.of(FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL,FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL)) {
            var s=session();s.accept(node(1,"old",ProvenanceStatus.VERIFIED));var before=s.snapshot();
            var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();store.fault=fault;
            try(var identity=key.identity()) {
                assertEquals(PUBLICATION_INCOMPLETE,DevicePresentationUpdate.publish(ROOT,s,identity,"rename",new byte[8],store).status());
                assertSame(before,s.snapshot());assertEquals(1,key.calls);assertEquals(1,store.calls);
                store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
                for(var e:store.snapshot().entrySet()) {read(e.getKey(),e.getValue());assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT,store.publish(e.getKey(),e.getValue()));}
                update(s,identity,"retry");
            }
        }
        var s=session();s.accept(node(1,"old",ProvenanceStatus.VERIFIED));
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {
            var store=new FakeV1ObjectPublicationStore();
            var exact=new V1ObjectPublicationStore(){
                public PublicationResult publish(ObjectId id,byte[] bytes)throws java.io.IOException {
                    assertNull(s.snapshot().object(id));read(id,bytes);store.seed(id,bytes);return store.publish(id,bytes);
                }
                public void close(){}
            };
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,"exact",new byte[8],exact);
            assertEquals(PUBLISHED,result.status());assertNotNull(s.snapshot().object(result.objectId()));
        }
    }
    @Test void missingIntermediateDisappearanceAndIntegrity() {
        var s=session();var a=node(1,"a",ProvenanceStatus.VERIFIED);var b=node(2,"b",ProvenanceStatus.VERIFIED,a.objectId());
        var c=node(3,"c",ProvenanceStatus.VERIFIED,b.objectId());s.accept(c);s.accept(a);
        assertEquals(Set.of(a.objectId(),c.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {assertEquals(2,update(s,identity,"all").parents().size());}
        s.replace(new AcceptedSnapshot(Map.of(c.objectId(),c),false));
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {assertEquals(List.of(c.objectId()),update(s,identity,"only present").parents());}
        s.replace(new AcceptedSnapshot(Map.of(a.objectId(),a,c.objectId(),c),false));s.accept(b);
        assertEquals(Set.of(c.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
        s.accept(node(1,"contradiction",ProvenanceStatus.VERIFIED));
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {
            assertThrows(IllegalStateException.class,()->DevicePresentationUpdate.publish(ROOT,s,identity,"no",new byte[8],new FakeV1ObjectPublicationStore()));
        }
    }

    @Test void realRenameLeavesTokenConsentValuesProvenanceAndTotpUnchanged() throws Exception {
        var s=session();for(int i=900;i<933;i++)s.accept(node(i,"old",ProvenanceStatus.VERIFIED));
        var a=R15SnapshotTest.token(1,R15SnapshotTest.value("a"));var b=R15SnapshotTest.token(2,R15SnapshotTest.value("b"));
        s.accept(a);s.accept(b);var heads=s.snapshot().topology().currentTokenHeads(a.tokenId());
        var desired=R15SnapshotTest.value("chosen");var c=a.value().credential();
        var credential=new V1Plaintext.Credential(c.algorithm(),c.digits(),c.period(),c.secret().bytes());
        String code=Totp.generate(credential,59);long generation=s.generation(a.tokenId());
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {
            var prepared=TokenResolutionConfirmation.prepare(ROOT,R15SnapshotTest.context(s),identity,a.tokenId(),desired,TokenUpdatePublication.Intent.ORDINARY);
            assertEquals(InitialTokenPublication.Status.CONFIRMATION_PREPARED,prepared.status());
            // Independently signed TOKEN with this identity remains verifiable after its DEVICE becomes historical.
            var signed=TokenWriter.signed(ROOT,identity,a.tokenId().bytes(),a.value(),new byte[8],List.of());
            var assertion=ProvenanceTest.valid(signed,ROOT);
            assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(assertion,ROOT,s.snapshot().verificationKeys()));
            var store=new FakeV1ObjectPublicationStore();
            assertEquals(PUBLISHED,DevicePresentationUpdate.publish(ROOT,s,identity,"new".repeat(85),new byte[8],store).status());
            assertEquals(3,store.calls);
            assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(assertion,ROOT,s.snapshot().verificationKeys()));
            assertEquals(heads,s.snapshot().topology().currentTokenHeads(a.tokenId()));
            assertEquals(a,s.snapshot().object(a.objectId()));assertEquals(b,s.snapshot().object(b.objectId()));
            assertEquals(code,Totp.generate(credential,59));assertEquals(generation,s.generation(a.tokenId()));
            assertTrue(prepared.confirmation().fresh(R15SnapshotTest.context(s),a.tokenId(),desired,TokenUpdatePublication.Intent.ORDINARY));
        }
    }

    @Test void verificationRetryChangesPresentationWithoutContradictingAuthenticatedEvidence() {
        var s=session();var a=node(1,"name",ProvenanceStatus.UNRESOLVED);s.accept(a);
        assertEquals(DevicePresentation.State.NONE,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
        s.accept(node(1,"name",ProvenanceStatus.VERIFIED));
        assertEquals(GraphIntegrityStatus.ACYCLIC,s.snapshot().topology().integrity());
        assertEquals(Set.of("name"),DevicePresentation.evaluate(s.snapshot(),DEVICE).names());
        var reversed=new LinkedHashMap<ObjectId,AcceptedObject>();
        var b=node(2,"other",ProvenanceStatus.VERIFIED);reversed.put(b.objectId(),b);reversed.put(a.objectId(),node(1,"name",ProvenanceStatus.VERIFIED));
        s.accept(b);
        assertEquals(DevicePresentation.evaluate(s.snapshot(),DEVICE),DevicePresentation.evaluate(new AcceptedSnapshot(reversed,false),DEVICE));
        assertThrows(UnsupportedOperationException.class,()->DevicePresentation.evaluate(s.snapshot(),DEVICE).names().clear());
    }

    @Test void incompleteSnapshotUnscopedAndCorruptBytesDoNotSupplyParents() {
        var s=session();var a=node(1,"a",ProvenanceStatus.VERIFIED);s.accept(a);
        s.accept(new OpaqueUnscopedRecord(GraphTopologyTest.id(2)));s.replace(new AcceptedSnapshot(s.snapshot().objects(),true));
        var invalid=new ObjectDiscovery().classify(GraphTopologyTest.id(3),new byte[1024],ROOT);
        assertNull(invalid.authenticated());
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {assertEquals(List.of(a.objectId()),update(s,identity,"new").parents());}
    }

    @Test void cycleAndSignerAnomalyNeverPublish() {
        var s=session();s.accept(node(1,"a",ProvenanceStatus.VERIFIED,GraphTopologyTest.id(2)));
        s.accept(node(2,"b",ProvenanceStatus.VERIFIED,GraphTopologyTest.id(1)));
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            assertThrows(IllegalStateException.class,()->DevicePresentationUpdate.publish(ROOT,s,identity,"new",new byte[8],store));
            assertEquals(0,key.calls);
            s.replace(GraphTopologyTest.state(node(1,"a",ProvenanceStatus.VERIFIED)));
            key.fixedSignature=new byte[0];
            assertEquals(SIGNING_FAILED,DevicePresentationUpdate.publish(ROOT,s,identity,"new",new byte[8],store).status());
            assertEquals(1,key.calls);assertEquals(0,store.calls);
            assertEquals(DEVICE_IDENTITY_UNAVAILABLE,DevicePresentationUpdate.publish(ROOT,s,identity,"new",new byte[8],store).status());
        }
    }

    @Test void authenticatedFutureBytesBlockOnlyTheirDeviceAndCorruptionIsNotOpaque() throws Exception {
        var fixture=ProvenanceTest.fixture("v1.crypto.future-device-opaque.001");
        var id=ObjectId.fromFilename(fixture.data().field("crypto").field("object_id").string());
        byte[] bytes=fixture.data().field("crypto").field("object_hex").hex();
        var observation=new ObjectDiscovery().classify(id,bytes,ROOT);
        assertEquals(ObjectDiscovery.Classification.OPAQUE_ROUTABLE,observation.classification());
        var s=session();s.accept(observation.authenticated().record());
        assertEquals(Set.of(id),s.snapshot().topology().currentDeviceHeads(DEVICE));
        assertEquals(DevicePresentation.State.OPAQUE,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
        assertTrue(DevicePresentation.evaluate(s.snapshot(),DEVICE).names().isEmpty());
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            assertEquals(OPAQUE_DEVICE_HEAD,DevicePresentationUpdate.publish(ROOT,s,identity,"blocked",new byte[8],store).status());
            assertEquals(0,key.calls);assertEquals(0,store.calls);
        }
        bytes[10]^=1;assertNull(new ObjectDiscovery().classify(id,bytes,ROOT).authenticated());
        var own=node(1,"own",ProvenanceStatus.VERIFIED);
        var foreign=new AcceptedDevice(id,2,SemanticStatus.OPAQUE_ROUTABLE,GraphTopologyTest.identity(700),List.of(),BigInteger.ZERO,null);
        s.replace(GraphTopologyTest.state(own,foreign));
        try(var identity=key.identity()){assertEquals(List.of(own.objectId()),update(s,identity,"allowed").parents());}
    }

    @Test void disappearanceAfterPlanningDoesNotRewriteParentsAndNewPlanUsesNewSnapshot() {
        var s=session();var a=node(1,"a",ProvenanceStatus.VERIFIED);s.accept(a);
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,"fixed",new byte[8],store,()->s.replace(AcceptedSnapshot.empty()));
            assertEquals(PUBLISHED,result.status());assertEquals(List.of(a.objectId()),read(result.objectId(),store.get(result.objectId())).parents());
            assertEquals(ParentEdgeStatus.UNRESOLVED,s.snapshot().topology().edgeStatus(result.objectId(),a.objectId()));
            s.replace(AcceptedSnapshot.empty());
            assertEquals(NO_EXISTING_DEVICE,DevicePresentationUpdate.publish(ROOT,s,identity,"empty",new byte[8],store).status());
            assertEquals(1,key.calls);assertEquals(1,store.calls);
        }
    }

    @Test void shortNamesHaveLargerStateDependentCapacity() {
        var s=session();for(int i=1;i<=22;i++)s.accept(node(i,"",ProvenanceStatus.VERIFIED));
        var key=new DeviceWriterTest.CapturingKey();
        try(var identity=key.identity()) {assertEquals(22,update(s,identity,"").parents().size());assertEquals(1,key.calls);}
    }
}
