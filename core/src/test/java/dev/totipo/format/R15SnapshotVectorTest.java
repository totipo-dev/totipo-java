package dev.totipo.format;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.io.IOException;
import java.math.BigInteger;
import java.util.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import static org.junit.jupiter.api.Assertions.*;

/** Symbolic graph evidence exercises production topology/policy; plans use real signed writers.
 * DEVICE rename publishes and independently authenticates real writer output.
 * Corruption actions model exclusion; real byte rejection is tested separately with NIO.
 */
class R15SnapshotVectorTest {
    @TestFactory List<DynamicTest> baselineGraphs() throws Exception {
        return VectorCaseLoader.baselineCases().stream().filter(c->c.data().field("operation").string().equals("graph"))
                .map(c->DynamicTest.dynamicTest(c.context(),()->new Runner(c.data().field("graph").field("steps").array()).run())).toList();
    }
    static final class Runner {
        final List<Node> steps;
        final SnapshotSession session=new SnapshotSession(new SecurityBytes(VaultLifecycleTest.binding(DeviceWriterTest.root()),32));
        final DeviceIdentityResult identity=new DeviceWriterTest.CapturingKey().identity();
        final Map<String,ObjectId> ids=new HashMap<>();
        final Map<String,AcceptedToken> authored=new HashMap<>();
        int cursor;
        Runner(List<Node> steps){this.steps=steps;}
        ObjectId id(String name){return ids.computeIfAbsent(name,n->new ObjectId(CryptoSupport.sha256(CryptoSupport.ascii(n))));}
        SecurityBytes identity(String name){return name.equals("D") ? new SecurityBytes(identity.deviceId(),32) : new SecurityBytes(id("identity:"+name).bytes(),32);}
        List<ObjectId> parents(Node n){return n.isNull()?List.of():DeviceWriter.canonicalParents(n.array().stream().map(x->id(x.string())).toList());}
        TokenValue value(Node n){byte[] secret=n.field("secret_hex").hex();return new TokenValue(n.field("status").string().equals("LIVE")?1:2,
                n.field("issuer").string(),n.field("account").string(),new TokenValue.Credential(n.field("algorithm").integer().intValueExact(),
                n.field("digits").integer().intValueExact(),n.field("period").integer().longValueExact(),new SecurityBytes(secret,secret.length)));}
        AcceptedObject object(Node step){
            var n=step.field("node");String name=n.field("id").string();
            if(authored.containsKey(name))return authored.get(name);
            String kind=n.field("class").string();
            if(kind.equals("OPAQUE_UNSCOPED"))return new OpaqueUnscopedRecord(id(name));
            boolean supported=kind.equals("SUPPORTED_VALID");
            var status=supported?SemanticStatus.SUPPORTED_VALID:SemanticStatus.OPAQUE_ROUTABLE;
            var time=n.field("author_time").integer();
            if(n.field("type").string().equals("TOKEN"))return new AcceptedToken(id(name),supported?1:2,status,identity(n.field("identity").string()),
                    parents(n.field("parents")),identity("author"),time,supported?value(step.field("value")):null);
            return new AcceptedDevice(id(name),supported?1:2,status,identity(n.field("identity").string()),parents(n.field("parents")),time,
                    supported?new SecurityBytes(DeviceWriterTest.KEY,65):null,
                    supported?(step.has("value")&&step.field("value").has("display_name")?step.field("value").field("display_name").string():""):null,
                    supported&&step.has("value")&&step.field("value").has("provenance")?ProvenanceStatus.valueOf(step.field("value").field("provenance").string()):ProvenanceStatus.UNRESOLVED);
        }
        void run() throws Exception {try(identity){while(cursor<steps.size())apply(steps.get(cursor++));}}
        void apply(Node step) throws Exception {
            switch(step.field("action").string()){
                case "learn" -> {
                    var o=object(step);
                    session.accept(o);
                    if(step.has("integrity_error")&&step.field("integrity_error").bool())assertNotEquals(GraphIntegrityStatus.ACYCLIC,session.snapshot().topology().integrity());
                }
                case "disappear", "remote-unavailable" -> {
                    var next=new HashMap<>(session.snapshot().objects());next.remove(id(step.field("id").string()));
                    session.replace(new AcceptedSnapshot(next,session.snapshot().incomplete()));
                }
                case "discovery-incomplete" -> session.replace(new AcceptedSnapshot(session.snapshot().objects(),step.field("flag").bool()));
                case "optional-cache-failure" -> { /* No optional cache exists or is invoked in baseline. */ }
                case "query" -> query(step);
                case "plan" -> plan(step);
                case "rename" -> {
                    var d=(AcceptedDevice)object(step);var heads=session.snapshot().topology().currentDeviceHeads(d.deviceId());
                    var store=new FakeV1ObjectPublicationStore();
                    var result=DevicePresentationUpdate.publish(DeviceWriterTest.root(),session,identity,d.displayName(),new byte[8],store);
                    assertEquals(step.field("success").bool(),result.status()==DevicePresentationUpdate.Status.PUBLISHED);
                    if(result.objectId()!=null){
                        var read=DevicePresentationUpdateTest.read(result.objectId(),store.get(result.objectId()));
                        assertEquals(heads,Set.copyOf(read.parents()));assertEquals(d.displayName(),read.displayName());
                        assertEquals(read,session.snapshot().object(result.objectId()));
                        ids.put(step.field("node").field("id").string(),result.objectId());
                    }else{assertEquals(DevicePresentationUpdate.Status.OPAQUE_DEVICE_HEAD,result.status());assertEquals(0,store.calls);}
                }
                case "state-query" -> {
                    var e=step.field("state_expect");var q=step.field("query");
                    assertEquals(new HashSet<>(parents(e.field("known"))),session.snapshot().objects().keySet());
                    assertEquals(new HashSet<>(parents(e.field("device_heads"))),session.snapshot().topology().currentDeviceHeads(identity(q.field("device").string())));
                    if(!step.field("id").string().isEmpty())assertEquals(parents(e.field("parents")),((AcceptedDevice)session.snapshot().object(id(step.field("id").string()))).parents());
                    assertEquals(e.field("integrity_ok").bool(),session.snapshot().topology().integrity()==GraphIntegrityStatus.ACYCLIC);
                }
                default -> fail("Unsupported graph action: "+step.field("action").string());
            }
        }
        TokenUpdatePublication.Context context(){return new TokenUpdatePublication.Context(new InitialDeviceAdvertisement.Context(session));}
        void plan(Node step) throws Exception {
            var n=step.field("node");var token=identity(n.field("identity").string());var desired=value(step.field("value"));
            var intent=step.field("intent").string().equals("restore")?TokenUpdatePublication.Intent.RESTORE:TokenUpdatePublication.Intent.ORDINARY;
            var heads=session.snapshot().topology().currentTokenHeads(token);
            assertEquals(new HashSet<>(parents(step.field("parents"))),heads);
            boolean confirmed=step.field("flag").bool();
            var confirmation=confirmed?TokenResolutionConfirmation.prepare(DeviceWriterTest.root(),context(),identity,token,desired,intent).confirmation():null;
            Node[] publication={null};boolean[] planned={false};
            Runnable afterPlan=()->{
                planned[0]=true;
                try{
                    while(cursor<steps.size()){
                        var next=steps.get(cursor++);
                        if(next.field("action").string().equals("publish")){publication[0]=next;break;}
                        apply(next);
                    }
                }catch(Exception e){throw new AssertionError(e);}
            };
            var store=new V1ObjectPublicationStore(){
                public PublicationResult publish(ObjectId objectId,byte[] bytes)throws IOException{
                    assertNotNull(publication[0]);
                    var a=AssertionValidator.validate(EnvelopeReader.open(objectId.filename(),bytes,DeviceWriterTest.root())).object();
                    assertEquals(ProvenanceStatus.VERIFIED,ProvenanceEvaluator.evaluate(a,DeviceWriterTest.root(),VerificationKeyMaterial.keys(identity.publicKeyX963())));
                    var accepted=(AcceptedToken)AuthenticatedObservation.supported(a).record();
                    assertEquals(heads,new HashSet<>(accepted.parents()));
                    ids.put(n.field("id").string(),objectId);authored.put(n.field("id").string(),accepted);
                    if(!publication[0].field("flag").bool())throw new IOException("Unacknowledged");
                    return PublicationResult.PUBLISHED_NEW;
                }
                public void close(){}
            };
            var result=confirmation!=null?TokenUpdatePublication.publishConfirmed(DeviceWriterTest.root(),this::context,identity,token,desired,new byte[8],intent,confirmation,store,List.of(),afterPlan)
                    :TokenUpdatePublication.publish(DeviceWriterTest.root(),this::context,identity,token,desired,new byte[8],intent,store,List.of(),afterPlan);
            assertEquals(step.field("success").bool(),planned[0]);
            if(publication[0]!=null)assertEquals(publication[0].field("success").bool(),result.receipt()!=null,result.status().toString());
        }
        void query(Node step){
            var q=step.field("query");var e=step.field("expect");var token=identity(q.field("identity").string());
            if(session.snapshot().topology().integrity()!=GraphIntegrityStatus.ACYCLIC){
                assertTrue(e.field("integrity_failure").bool());assertThrows(IllegalStateException.class,()->new TokenOperationPolicy(session.snapshot(),token));return;
            }
            assertFalse(e.field("integrity_failure").bool());
            var policy=new TokenOperationPolicy(session.snapshot(),token);var view=policy.current();
            assertEquals(new HashSet<>(parents(e.field("heads"))),view.currentHeadIds());
            String state=e.field("value_state").string().replace("VALUE_INCOMPLETE_OPAQUE","OPAQUE_CURRENT");
            assertEquals(state,view.state().name());assertEquals(e.field("ordinary").bool(),policy.ordinaryUse().eligible());
            boolean author=policy.authorship().stage()==TokenOperationPolicy.AuthorshipStage.CAN_PROCEED_TO_PLAN;
            assertEquals(e.field("author").bool(),author);
            var candidate=policy.candidates().get(id(q.field("candidate").string()));
            assertEquals(e.field("candidate").bool(),candidate!=null&&policy.candidateUse(candidate).eligible());
            assertEquals(e.field("candidate_warning").bool(),candidate!=null&&!policy.candidateUse(candidate).warnings().isEmpty());
            if(e.has("requires_confirmation"))assertEquals(e.field("requires_confirmation").bool(),view.state()==CurrentTokenValueState.CONFLICT);
            if(e.has("warnings"))for(var w:e.field("warnings").array())switch(w.string()){
                case "PROCESSING_INCOMPLETE" -> assertTrue(session.snapshot().incomplete());
                case "UNKNOWN_FUTURE_EVIDENCE" -> assertTrue(session.snapshot().hasUnscopedEvidence());
                default -> fail("Unclaimed warning");
            }
            if(e.has("presentation"))assertEquals(e.field("presentation").string(),
                    DevicePresentation.evaluate(session.snapshot(),identity(q.field("device").string())).state().name());
        }
    }
}
