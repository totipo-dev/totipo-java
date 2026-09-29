package dev.totipo.format;

import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DevicePresentationUpdateTest.*;
import static dev.totipo.format.DevicePresentationUpdate.Status.*;

class DeviceFoldTest {
    static final String MAX = "x".repeat(256);
    static SnapshotSession frontier(int count, String name) {
        var s=session();
        for(int i=count;i>0;i--)s.accept(node(i,name,ProvenanceStatus.VERIFIED));
        return s;
    }
    // Independent reader-produced ancestry oracle: unknown leaves must be exactly H0.
    static Map<ObjectId,AcceptedDevice> verify(FakeV1ObjectPublicationStore store, ObjectId last,
            Set<ObjectId> original, String name, byte[] time) {
        var nodes=new HashMap<ObjectId,AcceptedDevice>();
        store.snapshot().forEach((id,bytes)->{
            var d=read(id,bytes);nodes.put(id,d);
            assertEquals(name,d.displayName());assertEquals(new BigInteger(1,time),d.authorTime());
            assertEquals(DeviceWriter.canonicalParents(d.parents()),d.parents());
            assertTrue(d.parents().size()<=32);
            // Independent size calculation includes maximum signature, not observed DER length.
            assertTrue(213+name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length+36*d.parents().size()<=1006);
        });
        var leaves=new HashSet<ObjectId>();var visited=new HashSet<ObjectId>();
        var pending=new ArrayDeque<ObjectId>();pending.add(last);
        while(!pending.isEmpty()) {
            var id=pending.remove();assertTrue(visited.add(id),"No repeated consumption or cycle");
            if(nodes.containsKey(id))pending.addAll(nodes.get(id).parents());else leaves.add(id);
        }
        assertEquals(original,leaves);assertTrue(visited.containsAll(nodes.keySet()));
        // Walk the carry chain backwards, then check maximal deterministic original consumption.
        var chain=new ArrayList<AcceptedDevice>();var current=nodes.get(last);
        while(current!=null) {
            chain.add(current);
            var carries=current.parents().stream().filter(nodes::containsKey).toList();
            assertTrue(carries.size()<=1);current=carries.isEmpty()?null:nodes.get(carries.get(0));
        }
        Collections.reverse(chain);var ordered=original.stream().sorted(Comparator.comparing(ObjectId::filename)).toList();
        int consumed=0,k=Math.min(32,(1006-213-name.getBytes(java.nio.charset.StandardCharsets.UTF_8).length)/36);
        ObjectId carry=null;
        for(var d:chain) {
            int end=Math.min(ordered.size(),consumed+k-(carry==null?0:1));
            var expected=new HashSet<>(ordered.subList(consumed,end));if(carry!=null)expected.add(carry);
            assertEquals(expected,Set.copyOf(d.parents()));consumed=end;carry=d.objectId();
        }
        assertEquals(original.size(),consumed);return nodes;
    }
    @ParameterizedTest @ValueSource(ints={13,14,15,21,22,23,33,100})
    void directBoundariesAndWideCoverage(int n) {
        for(String name:List.of(MAX,"")) {
            var s=frontier(n,"old");var original=s.snapshot().topology().currentDeviceHeads(DEVICE);
            var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
            try(var identity=key.identity()) {
                var result=DevicePresentationUpdate.publish(ROOT,s,identity,name,new byte[8],store);
                assertEquals(PUBLISHED,result.status());int k=name.isEmpty()?22:14;
                int stages=(n-2)/(k-1)+1;assertEquals(stages,key.calls);assertEquals(stages,store.calls);
                verify(store,result.objectId(),original,name,new byte[8]);
                assertEquals(Set.of(result.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
                assertEquals(Set.of(name),DevicePresentation.evaluate(s.snapshot(),DEVICE).names());
            }
        }
    }
    @Test void capacityProgressForEveryPermittedByteLength() {
        for(int size=0;size<=256;size++) {
            int k=DeviceWriter.parentCapacity(size),bytes=size;
            assertTrue(k>=14&&k<=22&&k<=32);DeviceWriter.requireCapacity(size,k);
            assertThrows(IllegalArgumentException.class,()->DeviceWriter.requireCapacity(bytes,k+1));
        }
        assertEquals(14,DeviceWriter.parentCapacity(256));assertEquals(22,DeviceWriter.parentCapacity(0));
        assertThrows(IllegalArgumentException.class,()->DeviceWriter.parentCapacity(-1));
        assertThrows(IllegalArgumentException.class,()->DeviceWriter.parentCapacity(257));
        assertThrows(IllegalArgumentException.class,()->DeviceWriter.requireCapacity(0,33));
    }
    @ParameterizedTest @ValueSource(strings={"0000000000000000","8000000000000000","ffffffffffffffff"})
    void commonTimeAndEqualNameReaffirmationWithInertHeads(String raw) {
        var s=frontier(33,MAX);s.accept(node(34,"hostile",ProvenanceStatus.REJECTED));
        s.accept(node(35,"unavailable",ProvenanceStatus.UNRESOLVED));
        s.accept(new OpaqueUnscopedRecord(GraphTopologyTest.id(1000)));
        var original=s.snapshot().topology().currentDeviceHeads(DEVICE);
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        byte[] time=HexFormat.of().parseHex(raw),expected=time.clone();
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,time,store,()->Arrays.fill(time,(byte)0));
            assertEquals(PUBLISHED,result.status());verify(store,result.objectId(),original,MAX,expected);
            assertEquals(Set.of(result.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
            assertEquals(ProvenanceStatus.VERIFIED,((AcceptedDevice)s.snapshot().object(result.objectId())).provenance());
            assertTrue(DevicePresentation.evaluate(s.snapshot(),DEVICE).inertHeads().isEmpty());
        }
    }
    @ParameterizedTest @ValueSource(ints={14,20})
    void opaqueBlocksBeforeAnyStage(int count) {
        var s=frontier(count,"old");s.accept(new AcceptedDevice(GraphTopologyTest.id(1000),2,
                SemanticStatus.OPAQUE_ROUTABLE,DEVICE,List.of(),BigInteger.ZERO,null));
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {assertEquals(OPAQUE_DEVICE_HEAD,DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store).status());}
        assertEquals(0,key.calls);assertEquals(0,store.calls);
    }
    @Test void lateBranchStaysOutsideFixedOriginalFrontier() {
        var s=frontier(33,"old");var original=s.snapshot().topology().currentDeviceHeads(DEVICE);
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        var remote=node(1000,"remote",ProvenanceStatus.VERIFIED);
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store,()->{
                if(store.calls==1) {assertEquals(20,s.snapshot().topology().currentDeviceHeads(DEVICE).size());s.accept(remote);}
            });
            assertEquals(PUBLISHED,result.status());verify(store,result.objectId(),original,MAX,new byte[8]);
            assertEquals(Set.of(result.objectId(),remote.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
            assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void middlePublicationFailureRetainsOnlyAcknowledgedStages(boolean installed) {
        var s=frontier(33,"old");var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        store.afterSnapshot=()->{if(store.calls==2)store.fault=installed?FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL:FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;};
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store);
            assertEquals(PUBLICATION_INCOMPLETE,result.status());assertNull(result.objectId());
            assertEquals(2,key.calls);assertEquals(2,store.calls);
            assertEquals(34,s.snapshot().objects().size());
            assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
            assertEquals(installed?2:1,store.snapshot().size());
            store.snapshot().forEach((id,bytes)->s.accept(read(id,bytes)));
            assertEquals(installed?7:20,s.snapshot().topology().currentDeviceHeads(DEVICE).size());
            store.afterSnapshot=()->{};store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
            assertEquals(PUBLISHED,DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store).status());
            assertEquals(1,s.snapshot().topology().currentDeviceHeads(DEVICE).size());
        }
    }
    @ParameterizedTest @ValueSource(ints={1,2,3})
    void signerFailsOnceAtAttemptedStage(int stage) {
        var s=frontier(33,"old");var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        key.afterCapture=()->{if(key.calls==stage)key.fixedSignature=new byte[0];};
        try(var identity=key.identity()) {
            assertEquals(SIGNING_FAILED,DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store).status());
            assertEquals(stage,key.calls);assertEquals(stage-1,store.calls);assertEquals(33+stage-1,s.snapshot().objects().size());
        }
    }
    @Test void closedCapabilityIsNotReloadedBetweenStages() {
        var s=frontier(33,"old");var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        var identity=key.identity();store.afterSnapshot=identity::close;
        assertEquals(SIGNING_FAILED,DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store).status());
        assertEquals(1,key.calls);assertEquals(1,store.calls);assertEquals(34,s.snapshot().objects().size());
    }
    @Test void wideInvalidInputAndBindingMismatchNeverSign() {
        var s=frontier(33,"old");var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        try(var identity=key.identity()) {
            assertEquals(INVALID_DISPLAY_NAME,DevicePresentationUpdate.publish(ROOT,s,identity,"x".repeat(257),new byte[8],store).status());
            var wrong=new SnapshotSession(new SecurityBytes(new byte[32],32));wrong.replace(s.snapshot());
            assertEquals(DEVICE_IDENTITY_BINDING_MISMATCH,DevicePresentationUpdate.publish(ROOT,wrong,identity,MAX,new byte[8],store).status());
        }
        assertEquals(0,key.calls);assertEquals(0,store.calls);
    }
    @Test void ambiguousFreshRetryMayCreateOrdinarySiblingWithoutFence() {
        var s=frontier(33,"old");var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        store.afterSnapshot=()->{if(store.calls==2)store.fault=FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL;};
        try(var identity=key.identity()) {
            assertEquals(PUBLICATION_INCOMPLETE,DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store).status());
            var unseen=store.snapshot().keySet().stream().filter(id->s.snapshot().object(id)==null).findFirst().orElseThrow();
            store.afterSnapshot=()->{};store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
            var retry=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store);
            assertEquals(PUBLISHED,retry.status());assertNotEquals(unseen,retry.objectId());
            s.accept(read(unseen,store.get(unseen)));
            assertEquals(Set.of(unseen,retry.objectId()),s.snapshot().topology().currentDeviceHeads(DEVICE));
            assertEquals(DevicePresentation.State.VERIFIED,DevicePresentation.evaluate(s.snapshot(),DEVICE).state());
        }
    }
    @Test void exactExistingAcknowledgementAcceptsBeforeNextSign() {
        var s=frontier(33,"old");var original=s.snapshot().topology().currentDeviceHeads(DEVICE);
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        key.afterCapture=()->assertEquals(33+key.calls-1,s.snapshot().objects().size());
        var exact=new V1ObjectPublicationStore() {
            public PublicationResult publish(ObjectId id,byte[] bytes)throws IOException {
                assertNull(s.snapshot().object(id));store.seed(id,bytes);
                var ack=store.publish(id,bytes);assertEquals(PublicationResult.ALREADY_PRESENT_EXACT,ack);return ack;
            }
            public void close(){}
        };
        try(var identity=key.identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],exact);
            assertEquals(PUBLISHED,result.status());assertEquals(3,key.calls);assertEquals(3,store.calls);
            verify(store,result.objectId(),original,MAX,new byte[8]);
        }
    }
    @Test void peerMissingIntermediateDoesNotInventAncestryOrSuppressNames() {
        var s=frontier(15,"old");var base=s.snapshot();var store=new FakeV1ObjectPublicationStore();
        try(var identity=new DeviceWriterTest.CapturingKey().identity()) {
            var result=DevicePresentationUpdate.publish(ROOT,s,identity,MAX,new byte[8],store);
            var nodes=verify(store,result.objectId(),base.topology().currentDeviceHeads(DEVICE),MAX,new byte[8]);
            var last=nodes.get(result.objectId());var first=nodes.values().stream().filter(d->!d.objectId().equals(last.objectId())).findFirst().orElseThrow();
            var peer=session();peer.replace(base);peer.accept(read(last.objectId(),store.get(last.objectId())));
            assertEquals(ParentEdgeStatus.UNRESOLVED,peer.snapshot().topology().edgeStatus(last.objectId(),first.objectId()));
            assertEquals(15,peer.snapshot().topology().currentDeviceHeads(DEVICE).size());
            for(var id:first.parents())assertFalse(peer.snapshot().topology().ancestor(id,last.objectId()));
            assertEquals(DevicePresentation.State.CONFLICTED,DevicePresentation.evaluate(peer.snapshot(),DEVICE).state());
            peer.accept(read(first.objectId(),store.get(first.objectId())));
            assertEquals(Set.of(last.objectId()),peer.snapshot().topology().currentDeviceHeads(DEVICE));
            assertEquals(Set.of(MAX),DevicePresentation.evaluate(peer.snapshot(),DEVICE).names());
        }
    }
}
