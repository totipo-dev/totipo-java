package dev.totipo.format;

import java.math.BigInteger;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import static dev.totipo.format.TokenUpdatePublication.Intent.*;
import static dev.totipo.format.TokenUpdatePublicationTest.*;

class TokenResolutionConfirmationTest {
    static TokenResolutionConfirmation.Preparation prepare(Harness f, TokenValue desired) {
        return TokenResolutionConfirmation.prepare(f.h.root,f.context(),f.h.identity,TOKEN,desired,ORDINARY);
    }
    static TokenResolutionConfirmation confirm(Harness f, TokenValue desired) {
        int signs=f.h.keys.signs, writes=f.h.memory.appends, calls=f.h.store.calls;
        var p=prepare(f,desired);
        assertEquals(CONFIRMATION_PREPARED,p.status());assertNotNull(p.confirmation());
        assertEquals(signs,f.h.keys.signs);assertEquals(writes,f.h.memory.appends);assertEquals(calls,f.h.store.calls);
        assertEquals(f.policy().current(),p.current());
        assertEquals("TokenResolutionConfirmation[redacted]",p.confirmation().toString());
        return p.confirmation();
    }
    static InitialTokenPublication.Result publish(Harness f, TokenValue desired, TokenResolutionConfirmation c, Runnable hook) {
        return TokenUpdatePublication.publishConfirmed(f.h.root,f::context,f.h.identity,TOKEN,desired,time(-1),ORDINARY,c,f.h.store,f.ads,hook);
    }
    static Set<ObjectId> conflict(Harness f) throws Exception {
        var a=f.seed(value(),0,List.of());
        return Set.of(f.seed(value(),1,List.of(a)),f.seed(edit(1,"other","",77),2,List.of(a)));
    }
    @ParameterizedTest @ValueSource(strings={"X","Y","Z","delete","restore","unavailable","allMissing"})
    void completeResolution(String mode) throws Exception {
        try(var f=new Harness()) {
            f.ads.add(InitialTokenPublicationTest.evidence(f.h,f.h.run().objectId()));
            var heads=conflict(f);
            if(mode.equals("restore")) f.seed(edit(2,"deleted","",77),3,List.of());
            heads=f.context().graph().currentTokenHeads(TOKEN);
            if(mode.equals("unavailable")) f.unavailable.add(heads.iterator().next());
            if(mode.equals("allMissing")) f.unavailable.addAll(heads);
            var desired=switch(mode) {
                case "X","unavailable","allMissing" -> value();
                case "Y" -> edit(1,"other","",77);
                case "delete" -> edit(2,"deleted","",88);
                default -> edit(1,"third","new",99);
            };
            var c=confirm(f,desired);int signs=f.h.keys.signs;
            var r=publish(f,desired,c,()->{});f.check(r,desired,heads);
            assertEquals(signs+1,f.h.keys.signs);
            assertTrue(f.policy().current().unavailableSupportedHeadIds().isEmpty());
            assertTrue(f.unavailable.stream().allMatch(id->f.h.session.knowledge().record(id)!=null));
            assertEquals(CONFIRMATION_STALE,publish(f,desired,c,()->{}).status());
        }
    }
    @ParameterizedTest @ValueSource(strings={"ordinary","opaque","none","invalid","intent","discovery","unknown","blocked","unscoped","identity","binding"})
    void preparationBlocksWithoutSideEffects(String mode) throws Exception {
        try(var f=new Harness()) {
            if(!mode.equals("none")) f.seed(value(),0,List.of());
            if(!Set.of("ordinary","none").contains(mode)) f.seed(edit(1,"other","",77),1,List.of());
            var desired=value();var intent=ORDINARY;InitialTokenPublication.Status expected;
            switch(mode) {
                case "ordinary" -> expected=CONFIRMATION_NOT_REQUIRED;
                case "none" -> expected=NO_EXISTING_TOKEN;
                case "opaque" -> {opaque(f);expected=CURRENT_OPAQUE_BLOCKED;}
                case "invalid" -> {desired=edit(3,"","",1);expected=INVALID_VALUE;}
                case "intent" -> {intent=RESTORE;desired=edit(2,"","",1);expected=INVALID_UPDATE_INTENT;}
                case "identity" -> {f.h.identity.close();expected=DEVICE_IDENTITY_UNAVAILABLE;}
                case "binding" -> {f.h.root[0]=1;expected=DEVICE_IDENTITY_BINDING_MISMATCH;}
                default -> {change(f,mode);expected=AUTHORSHIP_NOT_READY;}
            }
            int signs=f.h.keys.signs, writes=f.h.memory.appends;
            var p=TokenResolutionConfirmation.prepare(f.h.root,f.context(),f.h.identity,TOKEN,desired,intent);
            assertEquals(expected,p.status());assertNull(p.confirmation());assertEquals(signs,f.h.keys.signs);
            assertEquals(writes,f.h.memory.appends);assertEquals(0,f.h.store.calls);
        }
    }
    static void opaque(Harness f) {
        f.h.session.commitRecord(new KnownTokenNode(InitialDeviceAdvertisementTest.id(8),2,SemanticStatus.OPAQUE_ROUTABLE,
                TOKEN,List.of(),new SecurityBytes(f.h.identity.deviceId(),32),BigInteger.ZERO));
    }
    static void change(Harness f,String mode) throws Exception {
        switch(mode) {
            case "newHead" -> f.seed(edit(1,"new","",3),8,List.of());
            case "opaque" -> opaque(f);
            case "availability" -> f.unavailable.add(f.context().graph().currentTokenHeads(TOKEN).iterator().next());
            case "revision","provenance" -> f.h.revision++;
            case "revert" -> {f.h.discovery=DiscoveryState.PROCESSING_INCOMPLETE;f.h.revision++;f.h.discovery=DiscoveryState.READY;f.h.revision++;}
            case "availabilityRevert" -> {var id=f.context().graph().currentTokenHeads(TOKEN).iterator().next();f.unavailable.add(id);f.h.revision++;f.unavailable.remove(id);f.h.revision++;}
            case "discovery" -> f.h.discovery=DiscoveryState.PROCESSING_INCOMPLETE;
            case "unknown" -> f.h.session.markUnknown();
            case "blocked" -> {f.h.memory.failAppend=true;f.h.session.commitRecord(InitialDeviceAdvertisementTest.node(f.h.identity,false,9));}
            case "unscoped" -> f.h.session.commitRecord(new OpaqueUnscopedRecord(InitialDeviceAdvertisementTest.id(9),new SecurityBytes(new byte[1024],1024)));
            case "identity" -> f.h.identity.close();
            case "restart" -> f.h.session=SecurityMemorySession.open(f.h.memory);
            default -> throw new AssertionError(mode);
        }
    }
    @ParameterizedTest @CsvSource({"newHead,false","newHead,true","opaque,false","opaque,true","availability,false","availability,true",
        "revision,false","revision,true","provenance,false","provenance,true","revert,false","revert,true",
        "availabilityRevert,false","availabilityRevert,true","discovery,false","discovery,true","unknown,false","unknown,true",
        "blocked,false","blocked,true","unscoped,false","unscoped,true","identity,false","identity,true","restart,false","restart,true"})
    void freshnessAtBothCheckpoints(String mode,boolean afterSign) throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());
            // The new-head test separately counts the remote-evidence fixture's signature.
            Runnable change=()->{try{change(f,mode);}catch(Exception e){throw new AssertionError(e);}};
            if(!afterSign)change.run();int signs=f.h.keys.signs;
            var r=publish(f,value(),c,afterSign?change:()->{});
            assertEquals(CONFIRMATION_STALE,r.status());assertNull(r.receipt());assertEquals(0,f.h.store.calls);
            assertEquals(signs+(afterSign?1:0)+(afterSign&&mode.equals("newHead")?1:0),f.h.keys.signs);
        }
    }
    @ParameterizedTest @ValueSource(strings={"token","value","status","algorithm","digits","period","secret","intent","null"})
    void exactChoiceAndIdentity(String mode) throws Exception {
        try(var f=new Harness()) {
            conflict(f);var desired=value();var c=confirm(f,desired);var token=TOKEN;var intent=ORDINARY;
            var cr=desired.credential();
            switch(mode) {
                case "token" -> {byte[] b=new byte[32];b[0]=1;token=new SecurityBytes(b,32);}
                case "value" -> desired=edit(1,"changed","",1);
                case "status" -> desired=new TokenValue(2,desired.issuer(),desired.account(),cr);
                case "intent" -> intent=RESTORE;
                case "null" -> c=null;
                default -> desired=new TokenValue(1,desired.issuer(),desired.account(),new TokenValue.Credential(
                        mode.equals("algorithm")?3:cr.algorithm(),mode.equals("digits")?8:cr.digits(),
                        mode.equals("period")?60:cr.period(),mode.equals("secret")?new SecurityBytes(new byte[]{99},1):cr.secret()));
            }
            int signs=f.h.keys.signs;
            assertEquals(CONFIRMATION_STALE,TokenUpdatePublication.publishConfirmed(f.h.root,f::context,f.h.identity,token,desired,
                    time(0),intent,c,f.h.store,f.ads).status());
            assertEquals(signs,f.h.keys.signs);assertEquals(0,f.h.store.calls);
        }
    }
    @Test void missingBecomesReadableAndRestartRequiresNewConsent() throws Exception {
        try(var f=new Harness()) {
            conflict(f);f.unavailable.addAll(f.context().graph().currentTokenHeads(TOKEN));var c=confirm(f,value());
            f.unavailable.clear();assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());
            c=confirm(f,value());f.h.session=SecurityMemorySession.open(f.h.memory);
            assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());
            var heads=f.context().graph().currentTokenHeads(TOKEN);
            f.check(publish(f,value(),confirm(f,value()),()->{}),value(),heads);
        }
    }
    @ParameterizedTest @ValueSource(ints={5,22,33})
    void capacityDoesNotDropParents(int count) throws Exception {
        try(var f=new Harness()) {
            for(int i=0;i<count;i++) f.seed(edit(1,"branch"+i,"",1),i,List.of());
            var desired=count==5?new TokenValue(1,"i".repeat(256),"a".repeat(256),new TokenValue.Credential(3,8,0xffffffffL,new SecurityBytes(new byte[128],128))):value();
            var c=confirm(f,desired);int signs=f.h.keys.signs;
            assertEquals(FOLD_REQUIRED,publish(f,desired,c,()->{}).status());
            assertEquals(signs,f.h.keys.signs);assertEquals(0,f.h.store.calls);assertEquals(count,f.context().graph().currentTokenHeads(TOKEN).size());
        }
    }
    @ParameterizedTest @ValueSource(strings={"before","ambiguous","graph"})
    void publicationFailureAndRecovery(String mode) throws Exception {
        try(var f=new Harness()) {
            var heads=conflict(f);var c=confirm(f,value());
            if(mode.equals("graph"))f.h.memory.failAppend=true;
            else f.h.store.fault=mode.equals("ambiguous")?FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL:FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;
            assertEquals(mode.equals("graph")?KNOWLEDGE_PERSISTENCE_FAILED:PUBLICATION_INCOMPLETE,publish(f,value(),c,()->{}).status());
            assertEquals(heads,f.context().graph().currentTokenHeads(TOKEN));
            int signs=f.h.keys.signs;
            assertEquals(mode.equals("graph")?CONFIRMATION_STALE:RECONCILIATION_REQUIRED,
                    publish(f,value(),c,()->{}).status());assertEquals(signs,f.h.keys.signs);
            f.h.memory.failAppend=false;f.h.session=SecurityMemorySession.open(f.h.memory);
            var source=new DiscoveryFixtures();f.h.store.snapshot().forEach(source::put);
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(source,f.h.root,f.h.session).discoveryState());
            assertEquals(mode.equals("before")?2:1,f.context().graph().currentTokenHeads(TOKEN).size());
        }
    }
    @Test void assertionValidityDoesNotRequireWriterConsent() throws Exception {
        try(var f=new Harness()) {
            var heads=conflict(f);
            f.blocked(CONFIRMATION_REQUIRED_CONFLICT,value(),ORDINARY);
            var child=f.seed(value(),99,DeviceWriter.canonicalParents(heads));
            assertEquals(Set.of(child),f.context().graph().currentTokenHeads(TOKEN));
            assertTrue(f.policy().ordinaryUse().eligible());
        }
    }
    @Test void restoreIntentIsExplicitAndBoundForConflictedLifecycle() throws Exception {
        try(var f=new Harness()) {
            conflict(f);f.seed(edit(2,"deleted","",3),3,List.of());var heads=f.context().graph().currentTokenHeads(TOKEN);
            var p=TokenResolutionConfirmation.prepare(f.h.root,f.context(),f.h.identity,TOKEN,value(),RESTORE);
            assertEquals(CONFIRMATION_PREPARED,p.status());
            assertEquals(CONFIRMATION_STALE,publish(f,value(),p.confirmation(),()->{}).status());
            f.check(TokenUpdatePublication.publishConfirmed(f.h.root,f::context,f.h.identity,TOKEN,value(),time(0),RESTORE,
                    p.confirmation(),f.h.store,f.ads),value(),heads);
        }
    }

    @ParameterizedTest @EnumSource(ProvenanceStatus.class)
    void provenanceAndMissingAncestryDoNotBlockConfirmedAuthorship(ProvenanceStatus provenance) throws Exception {
        try(var f=new Harness()) {
            var missing=InitialDeviceAdvertisementTest.id(19);
            var a=f.seed(value(),0,List.of(missing),f.h.identity,provenance);
            var b=f.seed(edit(1,"other","",77),1,List.of());
            assertEquals(ParentEdgeStatus.UNRESOLVED,f.context().graph().edgeStatus(a,missing));
            f.check(publish(f,value(),confirm(f,value()),()->{}),value(),Set.of(a,b));
            assertEquals(ParentEdgeStatus.UNRESOLVED,f.context().graph().edgeStatus(a,missing));
        }
    }

    @Test void signingFailureRevokesIdentityAndConsent() throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());
            f.h.keys.signFault=FakeDeviceKeyStore.SignFault.THROW;
            assertEquals(SIGNING_FAILED,publish(f,value(),c,()->{}).status());assertEquals(0,f.h.store.calls);
            f.h.keys.signFault=FakeDeviceKeyStore.SignFault.NONE;
            assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());
        }
    }

    @Test void interruptionBeforePublicationCanRetryWhileContextStillFresh() throws Exception {
        try(var f=new Harness()) {
            var heads=conflict(f);var c=confirm(f,value());
            assertThrows(IllegalStateException.class,()->publish(f,value(),c,()->{throw new IllegalStateException("Test interruption");}));
            assertEquals(0,f.h.store.calls);
            f.check(publish(f,value(),c,()->{}),value(),heads);
        }
    }
}
