package dev.totipo.format;

import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import static dev.totipo.format.TokenUpdatePublication.Intent.*;
import static dev.totipo.format.TokenUpdatePublicationTest.*;
import static dev.totipo.format.TokenResolutionConfirmationTest.*;

class TokenPublicationFenceTest {
    static DiscoveryFixtures source(Harness f) {
        var source=new DiscoveryFixtures();f.h.store.snapshot().forEach(source::put);return source;
    }
    static DiscoveryResult reconcile(Harness f, DiscoverySource source) {
        f.h.revision++;
        var result=f.h.session.tokenPublicationFence().reconcile(source,f.h.root,f.h.session);
        f.h.discovery=result.discoveryState();
        return result;
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void newConfirmationCannotBypassAmbiguityAndRealDiscoveryReconciles(boolean installed) throws Exception {
        try(var f=new Harness();var other=new Harness()) {
            var heads=conflict(f);var c1=confirm(f,value());var c0=confirm(f,value());
            other.seed(value(),0,List.of());
            var fence=f.h.session.tokenPublicationFence();assertFalse(fence.reconciliationRequired());
            f.h.store.fault=installed?FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL:FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;
            assertEquals(PUBLICATION_INCOMPLETE,publish(f,value(),c1,()->{}).status());
            assertTrue(fence.reconciliationRequired());assertEquals(heads,f.context().graph().currentTokenHeads(TOKEN));
            int signs=f.h.keys.signs,calls=f.h.store.calls,appends=f.h.memory.appends;
            // New contexts, unrelated revisions and repeated fresh preparation cannot clear it.
            for(int i=0;i<3;i++) {
                f.context();f.h.revision++;
                var p=prepare(f,value());assertEquals(RECONCILIATION_REQUIRED,p.status());assertNull(p.confirmation());
                assertEquals(RECONCILIATION_REQUIRED,publish(f,value(),c0,()->{}).status());
                assertEquals(RECONCILIATION_REQUIRED,f.update(value()).status());
            }
            assertEquals(RECONCILIATION_REQUIRED,publish(f,value(),c1,()->{}).status());
            assertEquals(signs,f.h.keys.signs);assertEquals(calls,f.h.store.calls);assertEquals(appends,f.h.memory.appends);
            assertEquals(PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED,other.update(value()).status());
            // Even discarding C1 cannot affect session state.
            c1=null;assertTrue(fence.reconciliationRequired());
            assertEquals(DiscoveryState.READY,reconcile(f,source(f)).discoveryState());
            assertFalse(fence.reconciliationRequired());assertEquals(calls,f.h.store.calls);assertEquals(signs,f.h.keys.signs);
            assertEquals(CONFIRMATION_STALE,publish(f,value(),c0,()->{}).status());
            if(installed) {
                var current=f.context().graph().currentTokenHeads(TOKEN);assertEquals(1,current.size());
                var child=current.iterator().next();heads.forEach(p->assertTrue(f.context().graph().ancestor(p,child)));
                assertEquals(CONFIRMATION_NOT_REQUIRED,prepare(f,value()).status());
                f.h.store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
                f.check(f.update(value()),value(),current);
            } else {
                assertEquals(heads,f.context().graph().currentTokenHeads(TOKEN));
                f.h.store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
                f.check(publish(f,value(),confirm(f,value()),()->{}),value(),heads);
            }
        }
    }
    @Test void ordinaryUpdatesShareFence() throws Exception {
        try(var f=new Harness()) {
            f.seed(value(),0,List.of());f.h.store.fault=FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL;
            assertEquals(PUBLICATION_INCOMPLETE,f.update(value()).status());int signs=f.h.keys.signs;
            assertEquals(RECONCILIATION_REQUIRED,f.update(value()).status());
            assertEquals(RECONCILIATION_REQUIRED,prepare(f,value()).status());
            assertEquals(signs,f.h.keys.signs);assertEquals(1,f.h.store.calls);
            reconcile(f,source(f));f.h.store.fault=FakeV1ObjectPublicationStore.Fault.NONE;
            assertEquals(PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED,f.update(value()).status());
        }
    }
    @ParameterizedTest @ValueSource(strings={"null","runtime","error"})
    void anyUnacknowledgedStoreExitRaisesFence(String mode) throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());int[] calls={0};
            var store=new V1ObjectPublicationStore() {
                public PublicationResult publishDurably(ObjectId id,byte[] bytes) {
                    calls[0]++;
                    if(mode.equals("runtime"))throw new IllegalStateException("Test failure");
                    if(mode.equals("error"))throw new AssertionError("Test error");
                    return null;
                }
                public void close() {}
            };
            java.util.function.Supplier<InitialTokenPublication.Result> run=()->TokenUpdatePublication.publishConfirmed(f.h.root,f::context,
                    f.h.identity,TOKEN,value(),time(0),ORDINARY,c,store,f.ads);
            if(mode.equals("error"))assertThrows(AssertionError.class,run::get);
            else assertEquals(PUBLICATION_INCOMPLETE,run.get().status());
            assertTrue(f.h.session.tokenPublicationFence().reconciliationRequired());assertEquals(1,calls[0]);
            assertEquals(RECONCILIATION_REQUIRED,prepare(f,value()).status());
        }
    }
    @ParameterizedTest @ValueSource(strings={"incomplete","persistence","unscoped"})
    void blockedReconciliationCannotClearFence(String mode) throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());f.h.store.fault=FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL;
            assertEquals(PUBLICATION_INCOMPLETE,publish(f,value(),c,()->{}).status());
            var source=source(f);
            if(mode.equals("incomplete"))source.issue=DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE;
            if(mode.equals("persistence"))f.h.memory.failAppend=true;
            if(mode.equals("unscoped"))f.h.session.commitRecord(new OpaqueUnscopedRecord(InitialDeviceAdvertisementTest.id(9),new SecurityBytes(new byte[1024],1024)));
            var result=reconcile(f,source);
            assertTrue(f.h.session.tokenPublicationFence().reconciliationRequired());
            assertEquals(RECONCILIATION_REQUIRED,prepare(f,value()).status());
            if(!mode.equals("unscoped"))assertEquals(DiscoveryState.PROCESSING_INCOMPLETE,result.discoveryState());
            if(mode.equals("incomplete")) {
                assertEquals(DiscoveryState.READY,reconcile(f,source(f)).discoveryState());
                assertFalse(f.h.session.tokenPublicationFence().reconciliationRequired());
            }
        }
    }
    @Test void successfulReconciliationInvalidatesOldConsentEvenWithoutOwnerRevisionChange() throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());f.h.store.fault=FakeV1ObjectPublicationStore.Fault.BEFORE_INSTALL;
            assertEquals(PUBLICATION_INCOMPLETE,publish(f,value(),c,()->{}).status());
            f.h.session.tokenPublicationFence().reconcile(source(f),f.h.root,f.h.session);
            assertFalse(f.h.session.tokenPublicationFence().reconciliationRequired());
            assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());
            assertEquals(CONFIRMATION_PREPARED,prepare(f,value()).status());
        }
    }
    @ParameterizedTest @ValueSource(strings={"stale","capacity","interrupt","signer"})
    void preStoreFailuresDoNotFence(String mode) throws Exception {
        try(var f=new Harness()) {
            conflict(f);
            if(mode.equals("capacity"))for(int i=0;i<33;i++)f.seed(value(),i+10,List.of());
            var c=confirm(f,value());
            switch(mode) {
                case "stale" -> {f.h.revision++;assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());}
                case "capacity" -> assertEquals(FOLD_REQUIRED,publish(f,value(),c,()->{}).status());
                case "interrupt" -> assertThrows(IllegalStateException.class,()->publish(f,value(),c,()->{throw new IllegalStateException("Test interruption");}));
                case "signer" -> {f.h.keys.signFault=FakeDeviceKeyStore.SignFault.THROW;assertEquals(SIGNING_FAILED,publish(f,value(),c,()->{}).status());}
            }
            assertFalse(f.h.session.tokenPublicationFence().reconciliationRequired());assertEquals(0,f.h.store.calls);
            if(!mode.equals("signer"))assertEquals(CONFIRMATION_PREPARED,prepare(f,value()).status());
        }
    }
    @ParameterizedTest @ValueSource(strings={"new","existing","graph"})
    void acknowledgedPublicationDoesNotFence(String mode) throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());
            var store=new V1ObjectPublicationStore() {
                public PublicationResult publishDurably(ObjectId id,byte[] bytes) throws IOException {
                    if(mode.equals("existing"))f.h.store.seed(id,bytes);
                    return f.h.store.publishDurably(id,bytes);
                }
                public void close() {}
            };
            if(mode.equals("graph"))f.h.memory.failAppend=true;
            var r=TokenUpdatePublication.publishConfirmed(f.h.root,f::context,f.h.identity,TOKEN,value(),time(0),ORDINARY,c,store,f.ads);
            assertEquals(mode.equals("graph")?KNOWLEDGE_PERSISTENCE_FAILED:PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED,r.status());
            assertFalse(f.h.session.tokenPublicationFence().reconciliationRequired());
        }
    }
    @Test void wrongRootCannotReconcileAndRestartDropsOnlyEphemeralFence() throws Exception {
        try(var f=new Harness()) {
            conflict(f);var c=confirm(f,value());f.h.store.fault=FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL;
            publish(f,value(),c,()->{});var wrongRoot=new byte[32];wrongRoot[0]=1;
            assertThrows(IllegalArgumentException.class,()->f.h.session.tokenPublicationFence().reconcile(source(f),wrongRoot,f.h.session));
            assertTrue(f.h.session.tokenPublicationFence().reconciliationRequired());
            f.h.session=SecurityMemorySession.open(f.h.memory);assertFalse(f.h.session.tokenPublicationFence().reconciliationRequired());
            reconcile(f,source(f));assertEquals(CONFIRMATION_STALE,publish(f,value(),c,()->{}).status());
            assertEquals(CONFIRMATION_NOT_REQUIRED,prepare(f,value()).status());
        }
    }
}
