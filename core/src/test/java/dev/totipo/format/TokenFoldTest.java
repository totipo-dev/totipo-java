package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import java.util.*;
import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.R15SnapshotTest.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;

class TokenFoldTest {
    static TokenValue max() { return TokenWriterTest.value(1,"I".repeat(256),"A".repeat(256),1,6,30,128); }
    static TokenValue min() { return TokenWriterTest.value(1,"","",1,6,30,1); }
    static SnapshotSession frontier(int n, TokenValue value, boolean conflict) throws Exception {
        var s=session();
        for(int i=n;i>0;i--)s.accept(token(i,conflict && i%2==0?value("other"):value));
        return s;
    }
    static InitialTokenPublication.Result run(SnapshotSession s, DeviceIdentityResult key, TokenValue value,
            byte[] time, TokenUpdatePublication.Intent intent, boolean confirmed, V1ObjectPublicationStore store, Runnable hook) {
        var c=confirmed?TokenResolutionConfirmation.prepare(ROOT,context(s),key,TokenValueFixtures.TOKEN,value,intent).confirmation():null;
        return confirmed?TokenUpdatePublication.publishConfirmed(ROOT,()->context(s),key,TokenValueFixtures.TOKEN,value,time,intent,c,store,List.of(),hook)
                :TokenUpdatePublication.publish(ROOT,()->context(s),key,TokenValueFixtures.TOKEN,value,time,intent,store,List.of(),hook);
    }
    static List<AcceptedToken> read(FakeV1ObjectPublicationStore store, TokenValue value, byte[] time) {
        var nodes=new ArrayList<AcceptedToken>();
        store.snapshot().forEach((id,bytes)->{
            var envelope=EnvelopeReader.open(id.filename(),bytes,ROOT);
            var validated=AssertionValidator.validate(envelope).object();
            assertNotNull(validated);
            assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(validated,ROOT,VerificationKeyMaterial.keys(DeviceWriterTest.KEY)));
            var node=(AcceptedToken)AuthenticatedObservation.supported(validated).record();
            assertEquals(value,node.value());assertEquals(TokenValueFixtures.TOKEN,node.tokenId());
            assertEquals(new SecurityBytes(P256.deviceId(DeviceWriterTest.KEY),32),node.authorDeviceId());
            assertEquals(new java.math.BigInteger(1,time),node.authorTime());
            assertEquals(DeviceWriter.canonicalParents(node.parents()),node.parents());
            assertTrue(node.parents().size()<=TokenWriter.parentCapacity(value));
            assertFalse(node.parents().contains(id));nodes.add(node);
        });
        return nodes;
    }
    // Independent iterative oracle walks reader-produced claims, never planner bookkeeping.
    static Set<ObjectId> ancestors(ObjectId last, Map<ObjectId,AcceptedToken> nodes) {
        var seen=new HashSet<ObjectId>();var pending=new ArrayDeque<ObjectId>();pending.add(last);
        while(!pending.isEmpty()){
            var n=pending.remove();if(!seen.add(n))continue;
            if(nodes.containsKey(n))pending.addAll(nodes.get(n).parents());
        }
        seen.remove(last);return seen;
    }
    @ParameterizedTest @ValueSource(ints={1,2,3,4,5,21,22,33,100})
    void boundaryAndStressCoverage(int n) throws Exception {
        for(var value:List.of(min(),max(),value("representative"))){
            int k=TokenWriter.parentCapacity(value);var s=frontier(n,value,false);
            var original=s.snapshot().topology().currentTokenHeads(TokenValueFixtures.TOKEN);
            var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();byte[] time=ByteBuffer.allocate(8).putLong(-1).array();
            var result=run(s,key.identity(),value,time,TokenUpdatePublication.Intent.ORDINARY,false,store,()->{});
            assertEquals(PUBLISHED_DEVICE_REQUIRED,result.status());
            int stages=Math.max(1,(n-2+k-1)/(k-1));assertEquals(stages,key.calls);assertEquals(stages,store.calls);
            var nodes=new HashMap<ObjectId,AcceptedToken>();read(store,value,time).forEach(t->nodes.put(t.objectId(),t));
            var visited=ancestors(result.receipt().objectId(),nodes);assertTrue(visited.containsAll(original));
            var leaves=new HashSet<>(visited);leaves.removeAll(nodes.keySet());assertEquals(original,leaves);
            assertEquals(Set.of(result.receipt().objectId()),s.snapshot().topology().currentTokenHeads(TokenValueFixtures.TOKEN));
            var ordered=original.stream().sorted(Comparator.comparing(ObjectId::filename)).toList();
            var first=nodes.values().stream().filter(t->t.parents().stream().allMatch(original::contains)).findFirst().orElseThrow();
            assertEquals(ordered.subList(0,Math.min(n,k)),first.parents());
        }
    }
    @Test void capacityAroundEachBoundary() {
        for(var value:List.of(min(),max(),value("representative"))){
            int k=TokenWriter.parentCapacity(value);assertTrue(k>=2);
            TokenWriter.requireCapacity(value,k-1);TokenWriter.requireCapacity(value,k);
            assertThrows(IllegalArgumentException.class,()->TokenWriter.requireCapacity(value,k+1));
        }
        assertEquals(4,TokenWriter.parentCapacity(max()));assertEquals(21,TokenWriter.parentCapacity(min()));
    }
    @ParameterizedTest @ValueSource(strings={"edit","rotate","delete","restore","reaffirm-tombstone","conflict","third"})
    void completeValuesAndIntents(String operation) throws Exception {
        var old=max();var desired=max();var intent=TokenUpdatePublication.Intent.ORDINARY;
        switch(operation){
            case "edit","third" -> desired=new TokenValue(1,"Z".repeat(256),old.account(),old.credential());
            case "rotate" -> desired=new TokenValue(1,old.issuer(),old.account(),min().credential());
            case "delete" -> desired=new TokenValue(2,old.issuer(),old.account(),old.credential());
            case "restore" -> {old=new TokenValue(2,old.issuer(),old.account(),old.credential());intent=TokenUpdatePublication.Intent.RESTORE;}
            case "reaffirm-tombstone" -> {old=new TokenValue(2,old.issuer(),old.account(),old.credential());desired=old;}
            default -> {}
        }
        boolean conflict=Set.of("conflict","third").contains(operation);var s=frontier(33,old,conflict);
        var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
        if(conflict)assertEquals(CONFIRMATION_REQUIRED_CONFLICT,run(s,key.identity(),desired,new byte[8],intent,false,store,()->{}).status());
        var result=run(s,key.identity(),desired,new byte[8],intent,conflict,store,()->{});
        assertNotNull(result.receipt());read(store,desired,new byte[8]);
        assertEquals(Set.of(desired),CurrentTokenValueEvaluator.evaluate(s.snapshot(),TokenValueFixtures.TOKEN).distinctValues());
    }
    @ParameterizedTest @ValueSource(ints={1,2,3})
    void signingAndPublicationFailuresStopExactly(int failure) throws Exception {
        for(String kind:List.of("sign","before","after")){
            var s=frontier(10,max(),false);var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
            key.afterCapture=()->{if(kind.equals("sign") && key.calls==failure)throw new IllegalStateException("Injected signer failure");};
            store.afterSnapshot=()->{if(store.calls==failure)store.fault=kind.equals("after")?FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL:kind.equals("before")?FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL:FakeV1ObjectPublicationStore.Fault.NONE;};
            var result=run(s,key.identity(),max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,store,()->{});
            assertEquals(kind.equals("sign")?SIGNING_FAILED:PUBLICATION_INCOMPLETE,result.status());
            assertEquals(failure,key.calls);assertEquals(kind.equals("sign")?failure-1:failure,store.calls);
            assertEquals(10+failure-1,s.snapshot().objects().size());
            assertEquals(failure-1+(kind.equals("after")?1:0),store.snapshot().size());
            read(store,max(),new byte[8]);
        }
    }
    @Test void confirmationFreshnessAndExternalEvents() throws Exception {
        for(String event:List.of("before","during-sign","during-publish","unrelated","none")){
            var s=frontier(10,max(),true);var key=new DeviceWriterTest.CapturingKey();var identity=key.identity();var store=new FakeV1ObjectPublicationStore();
            var second=TokenResolutionConfirmation.prepare(ROOT,context(s),identity,TokenValueFixtures.TOKEN,max(),TokenUpdatePublication.Intent.ORDINARY).confirmation();
            var remote=token(500,value("remote"));
            key.afterCapture=()->{if(key.calls==1 && event.equals("during-sign"))s.accept(remote);};
            store.afterSnapshot=()->{if(store.calls==1){
                if(event.equals("during-publish"))s.accept(remote);
                if(event.equals("unrelated")){s.accept(GraphTopologyTest.node(true,501,502,1));s.accept(GraphTopologyTest.node(false,502,503,1));}
            }};
            var result=run(s,identity,max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,true,store,()->{if(event.equals("before"))s.accept(remote);});
            boolean stale=Set.of("before","during-sign","during-publish").contains(event);
            assertEquals(stale?CONFIRMATION_STALE:PUBLISHED_DEVICE_REQUIRED,result.status());
            assertEquals(event.equals("before")?0:event.equals("during-sign")?1:event.equals("during-publish")?1:3,key.calls);
            assertEquals(event.equals("before")||event.equals("during-sign")?0:event.equals("during-publish")?1:3,store.calls);
            assertFalse(second.fresh(context(s),TokenValueFixtures.TOKEN,max(),TokenUpdatePublication.Intent.ORDINARY));
        }
    }
    @Test void ordinaryConcurrencyAndSnapshotReplacementDoNotChangePlan() throws Exception {
        for(boolean remove:List.of(false,true)){
            var s=frontier(10,max(),false);var original=s.snapshot();var remote=token(500,value("remote"));
            var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();byte[] time=new byte[8];
            store.afterSnapshot=()->{if(store.calls==1){Arrays.fill(time,(byte)9);if(remove)s.replace(AcceptedSnapshot.empty());else s.accept(remote);}};
            var result=run(s,key.identity(),max(),time,TokenUpdatePublication.Intent.ORDINARY,false,store,()->{});
            assertNotNull(result.receipt());var nodes=new HashMap<ObjectId,AcceptedToken>();read(store,max(),new byte[8]).forEach(t->nodes.put(t.objectId(),t));
            assertTrue(ancestors(result.receipt().objectId(),nodes).containsAll(original.objects().keySet()));
            assertFalse(ancestors(result.receipt().objectId(),nodes).contains(remote.objectId()));
            if(!remove)assertEquals(2,s.snapshot().topology().currentTokenHeads(TokenValueFixtures.TOKEN).size());
        }
    }
    @Test void peerDoesNotInventMissingIntermediateAncestry() throws Exception {
        var s=frontier(5,max(),false);var originals=s.snapshot();var store=new FakeV1ObjectPublicationStore();
        var r=run(s,new DeviceWriterTest.CapturingKey().identity(),max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,store,()->{});
        var nodes=read(store,max(),new byte[8]);var last=nodes.stream().filter(t->t.objectId().equals(r.receipt().objectId())).findFirst().orElseThrow();
        var first=nodes.stream().filter(t->!t.equals(last)).findFirst().orElseThrow();
        var peer=originals.accepting(last);assertEquals(ParentEdgeStatus.UNRESOLVED,peer.topology().edgeStatus(last.objectId(),first.objectId()));
        assertFalse(peer.topology().ancestor(first.parents().get(0),last.objectId()));
        peer=peer.accepting(first);assertTrue(peer.topology().ancestor(first.parents().get(0),last.objectId()));
    }
    @Test void commonTimeVectorDrivesActualFold() throws Exception {
        var vector=VectorCaseLoader.timestampCases().stream().filter(c->c.id().equals("v1.timestamp.fold-common-time.001")).findFirst().orElseThrow();
        var steps=vector.data().field("graph").field("steps").array();
        var time=steps.get(1).field("node").field("author_time").integer();
        assertEquals(time,steps.get(2).field("node").field("author_time").integer());
        byte[] raw=ByteBuffer.allocate(8).putLong(time.longValue()).array();
        var s=frontier(33,max(),false);var store=new FakeV1ObjectPublicationStore();
        assertNotNull(run(s,new DeviceWriterTest.CapturingKey().identity(),max(),raw,TokenUpdatePublication.Intent.ORDINARY,false,store,()->{}).receipt());
        assertEquals(11,read(store,max(),raw).size());
    }

    @Test void pinnedMaximumValuesDriveBoundaryPublication() throws Exception {
        for(var vector:VectorCaseLoader.cases("size")){
            if(!vector.id().startsWith("v1.size.token-"))continue;
            var v=vector.data().field("input");byte[] secret=v.field("secret").base64();
            var value=new TokenValue(v.field("status").integer().intValueExact(),v.field("issuer").string(),v.field("account").string(),
                    new TokenValue.Credential(v.field("algorithm").integer().intValueExact(),v.field("digits").integer().intValueExact(),
                            v.field("period").integer().longValueExact(),new SecurityBytes(secret,secret.length)));
            int n=v.field("parents").array().size();var s=frontier(n,value,false);var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
            assertNotNull(run(s,key.identity(),value,new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,store,()->{}).receipt());
            assertEquals(n==4?1:2,key.calls);read(store,value,new byte[8]);
        }
    }

    @Test void opaqueAndInvalidIntentSignNothing() throws Exception {
        for(String mode:List.of("opaque","intent","restore")){
            var value=max();if(mode.equals("restore"))value=new TokenValue(2,value.issuer(),value.account(),value.credential());
            var s=frontier(33,value,false);if(mode.equals("opaque"))s.accept(TokenValueFixtures.opaque(500));
            var key=new DeviceWriterTest.CapturingKey();var store=new FakeV1ObjectPublicationStore();
            var result=run(s,key.identity(),max(),new byte[8],mode.equals("intent")?TokenUpdatePublication.Intent.RESTORE:TokenUpdatePublication.Intent.ORDINARY,false,store,()->{});
            assertEquals(mode.equals("opaque")?CURRENT_OPAQUE_BLOCKED:mode.equals("intent")?INVALID_UPDATE_INTENT:RESTORATION_INTENT_REQUIRED,result.status());
            assertEquals(0,key.calls);assertEquals(0,store.calls);
        }
    }

    @Test void exactExistingAcknowledgementContinuesAndUnambiguousPartialCanResume() throws Exception {
        var s=frontier(10,max(),false);var acceptedSession=s;var store=new FakeV1ObjectPublicationStore();var key=new DeviceWriterTest.CapturingKey();
        V1ObjectPublicationStore exact=new V1ObjectPublicationStore(){
            public PublicationResult publish(ObjectId id,byte[] bytes)throws java.io.IOException{
                assertNull(acceptedSession.snapshot().object(id));store.seed(id,bytes);
                var result=store.publish(id,bytes);assertEquals(PublicationResult.ALREADY_PRESENT_EXACT,result);return result;
            }
            public void close(){}
        };
        assertNotNull(run(s,key.identity(),max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,exact,()->{}).receipt());
        assertEquals(3,key.calls);assertEquals(3,store.calls);
        s=frontier(10,max(),false);var original=s.snapshot();var interrupted=new FakeV1ObjectPublicationStore();
        interrupted.afterSnapshot=()->{if(interrupted.calls==2)interrupted.fault=FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;};
        assertEquals(PUBLICATION_INCOMPLETE,run(s,key.identity(),max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,interrupted,()->{}).status());
        var restart=session();restart.replace(original);read(interrupted,max(),new byte[8]).forEach(restart::accept);
        assertEquals(CurrentTokenValueState.UNAMBIGUOUS,CurrentTokenValueEvaluator.evaluate(restart.snapshot(),TokenValueFixtures.TOKEN).state());
        assertNotNull(run(restart,key.identity(),max(),new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,new FakeV1ObjectPublicationStore(),()->{}).receipt());
    }

    @Test void deterministicTestSignerProducesShortNormalAndMaximumDerWithoutChangingChunks() throws Exception {
        var random=java.security.SecureRandom.getInstance("SHA1PRNG");random.setSeed(new byte[]{1,2,3,4});
        var privateKey=java.security.KeyFactory.getInstance("EC").generatePrivate(new java.security.spec.ECPrivateKeySpec(
                java.math.BigInteger.ONE,P256.decode(DeviceWriterTest.KEY).getParams()));
        var lengths=new HashSet<Integer>();var calls=new int[1];
        DeviceProvenanceKey key=new DeviceProvenanceKey(){
            public byte[] vaultBinding(){return VaultLifecycleTest.binding(ROOT);}
            public byte[] publicKeyX963(){return DeviceWriterTest.KEY.clone();}
            public byte[] signSha256Ecdsa(byte[] input)throws java.security.GeneralSecurityException{
                calls[0]++;var signer=java.security.Signature.getInstance("SHA256withECDSA");
                signer.initSign(privateKey,random);signer.update(input);byte[] signature=signer.sign();lengths.add(signature.length);return signature;
            }
            public void close(){}
        };
        var identity=DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND,key,key.vaultBinding(),key.publicKeyX963());
        // 4 extra reserved bytes would admit the fifth parent if actual short DER were used.
        var value=TokenWriterTest.value(1,"i".repeat(256),"a".repeat(256),1,6,30,100);
        assertEquals(4,TokenWriter.parentCapacity(value));var s=frontier(100,value,false);var store=new FakeV1ObjectPublicationStore();
        assertNotNull(run(s,identity,value,new byte[8],TokenUpdatePublication.Intent.ORDINARY,false,store,()->{}).receipt());
        assertTrue(lengths.containsAll(Set.of(70,71,72)));assertEquals(33,calls[0]);assertEquals(33,store.calls);
        read(store,value,new byte[8]);
    }
}
