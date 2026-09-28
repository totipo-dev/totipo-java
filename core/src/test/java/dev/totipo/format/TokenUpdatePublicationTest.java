package dev.totipo.format;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.*;
import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.InitialTokenPublication.Status.*;
import static dev.totipo.format.TokenUpdatePublication.Intent.*;

class TokenUpdatePublicationTest {
    static final SecurityBytes TOKEN = new SecurityBytes(new byte[32], 32);
    static TokenValue value() { return InitialTokenPublicationTest.value(); }
    static TokenValue edit(int status, String issuer, String account, int secret) {
        return new TokenValue(status, issuer, account, new TokenValue.Credential(1, 6, 30,
                new SecurityBytes(new byte[]{(byte) secret}, 1)));
    }
    static class Harness implements AutoCloseable {
        final InitialDeviceAdvertisementTest.Harness h = new InitialDeviceAdvertisementTest.Harness();
        final Set<ObjectId> unavailable = new HashSet<>();
        final List<TokenPublicationSuccessGate.VerifiedDeviceAdvertisement> ads = new ArrayList<>();
        Harness() throws Exception {}
        TokenUpdatePublication.Context context() {
            var g = new GraphTopology(h.session.knowledge());
            var values = new ArrayList<ReadableTokenValue>();
            h.store.snapshot().forEach((id, bytes) -> {
                if (!unavailable.contains(id) && h.session.knowledge().record(id) instanceof KnownTokenNode n
                        && n.semanticStatus() == SemanticStatus.SUPPORTED_VALID) {
                    values.add(ReadableTokenValue.supported(AssertionValidator.validate(
                            EnvelopeReader.open(id.filename(), bytes, new byte[32])).object()));
                }
            });
            return new TokenUpdatePublication.Context(h.context(), g, new CurrentReadableValues(g, values));
        }
        ObjectId seed(TokenValue value, long time, List<ObjectId> parents) throws Exception {
            return seed(value, time, parents, h.identity, ProvenanceStatus.VERIFIED);
        }
        ObjectId seed(TokenValue value, long time, List<ObjectId> parents, DeviceIdentityResult author,
                      ProvenanceStatus provenance) throws Exception {
            byte[] bytes = TokenWriter.signed(h.root, author, TOKEN.bytes(), value, time(time), parents);
            if (provenance == ProvenanceStatus.REJECTED) bytes[bytes.length - 1] ^= 1;
            var object = V1EnvelopeWriter.seal(h.root, bytes);
            h.store.seed(object.id(), object.bytes());
            var assertion = AssertionValidator.validate(EnvelopeReader.open(object.id().filename(), object.bytes(), h.root)).object();
            assertEquals(provenance, ProvenanceEvaluator.evaluate(assertion, h.root,
                    provenance == ProvenanceStatus.UNRESOLVED ? VerificationKeyMaterial.keys()
                            : VerificationKeyMaterial.keys(author.publicKeyX963())));
            h.session.commit(AuthenticatedObservation.supported(assertion));
            return object.id();
        }
        InitialTokenPublication.Result update(TokenValue value) { return update(value, ORDINARY, () -> {}); }
        InitialTokenPublication.Result update(TokenValue value, TokenUpdatePublication.Intent intent, Runnable hook) {
            return TokenUpdatePublication.publish(h.root, this::context, h.identity, TOKEN, value, time(1), intent, h.store, ads, hook);
        }
        TokenOperationPolicy policy() {
            var c = context();
            return new TokenOperationPolicy(new VaultReadiness(h.session.knowledge(), h.discovery), c.graph(), TOKEN, c.readable());
        }
        void blocked(InitialTokenPublication.Status status, TokenValue desired, TokenUpdatePublication.Intent intent) {
            int signs = h.keys.signs, calls = h.store.calls, appends = h.memory.appends;
            var result = update(desired, intent, () -> {});
            assertEquals(status, result.status()); assertNull(result.receipt());
            assertEquals(signs, h.keys.signs); assertEquals(calls, h.store.calls); assertEquals(appends, h.memory.appends);
        }
        void check(InitialTokenPublication.Result result, TokenValue desired, Set<ObjectId> parents) {
            assertEquals(ads.isEmpty() ? PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED : PUBLISHED_AND_REMEMBERED_SUCCESS_READY, result.status());
            assertEquals(TOKEN, result.receipt().tokenId());
            var id = result.receipt().objectId();
            var node = (KnownTokenNode) h.session.knowledge().record(id);
            assertEquals(DeviceWriter.canonicalParents(parents), node.parents());
            assertEquals(Set.of(id), context().graph().currentTokenHeads(TOKEN));
            parents.forEach(p -> assertTrue(context().graph().ancestor(p, id)));
            assertEquals(Set.of(desired), policy().current().distinctReadableValues());
            assertEquals(desired.status() == 1, policy().ordinaryUse().eligible());
            byte[] bytes = h.store.get(id); assertEquals(1024, bytes.length);
            var assertion = AssertionValidator.validate(EnvelopeReader.open(id.filename(), bytes, h.root));
            assertEquals(AssertionValidator.Status.ASSERTION_VALID, assertion.status());
            assertEquals(ProvenanceStatus.VERIFIED, ProvenanceEvaluator.evaluate(assertion.object(), h.root,
                    VerificationKeyMaterial.keys(h.identity.publicKeyX963())));
            byte[] wrongRoot = h.root.clone(); wrongRoot[0] ^= 1;
            assertEquals(ProvenanceStatus.REJECTED, ProvenanceEvaluator.evaluate(assertion.object(), wrongRoot,
                    VerificationKeyMaterial.keys(h.identity.publicKeyX963())));
        }
        @Override public void close() { h.close(); }
    }
    static byte[] time(long time) { return ByteBuffer.allocate(8).putLong(time).array(); }

    @Test void sequentialWholeStateLifecycleAndRestart() throws Exception {
        try (var f = new Harness()) {
            f.ads.add(InitialTokenPublicationTest.evidence(f.h, f.h.run().objectId()));
            ObjectId previous = f.seed(value(), -1, List.of());
            var original = f.h.store.get(previous);
            var originalId = previous;
            var edits = List.of(edit(1,"issuer","",42), edit(1,"issuer","account",42),
                    edit(1,"both","both",42), edit(1,"both","both",77),
                    edit(2,"both","both",77), edit(2,"both","both",88), edit(1,"restored","both",88),
                    edit(1,"restored","both",88));
            for (int i = 0; i < edits.size(); i++) {
                var desired = edits.get(i);
                var intent = i == 6 ? RESTORE : ORDINARY;
                int signs = f.h.keys.signs;
                var result = f.update(desired, intent, () -> {});
                assertEquals(signs + 1, f.h.keys.signs);
                f.check(result, desired, Set.of(previous)); previous = result.receipt().objectId();
            }
            f.h.session = SecurityMemorySession.open(f.h.memory);
            var source = new DiscoveryFixtures(); f.h.store.snapshot().forEach(source::put);
            assertEquals(DiscoveryState.READY, DiscoveryCoordinator.discover(source, f.h.root, f.h.session).discoveryState());
            assertEquals(Set.of(previous), f.context().graph().currentTokenHeads(TOKEN));
            assertEquals(Set.of(edits.get(edits.size()-1)), f.policy().current().distinctReadableValues());
            assertArrayEquals(original, f.h.store.get(originalId));
            var selected = f.policy().ordinaryUse().value().orElseThrow().credential();
            var parsed = EnvelopeReader.open(previous.filename(), f.h.store.get(previous), f.h.root).plaintext();
            assertEquals(Totp.generate(new V1Plaintext.Credential(selected.algorithm(), selected.digits(), selected.period(), selected.secret().bytes()), 59),
                    Totp.generate(parsed.token().credential(), 59));
            var oldParsed = EnvelopeReader.open(originalId.filename(), original, f.h.root).plaintext();
            assertNotEquals(Totp.generate(oldParsed.token().credential(),59), Totp.generate(parsed.token().credential(),59));
        }
    }
    @ParameterizedTest @ValueSource(booleans = {false,true})
    void equalConcurrentHeads(boolean changed) throws Exception {
        try (var f = new Harness(); var other = new InitialDeviceAdvertisementTest.Harness()) {
            var a = f.seed(value(), 99, List.of());
            var b = f.seed(value(), -1, List.of(a));
            var c = f.seed(value(), 0, List.of(a), other.identity, ProvenanceStatus.UNRESOLVED);
            var desired = changed ? edit(1,"new","account",99) : value();
            f.check(f.update(desired), desired, Set.of(b,c));
        }
    }
    @ParameterizedTest @EnumSource(ProvenanceStatus.class)
    void parentProvenanceDoesNotAffectCausality(ProvenanceStatus status) throws Exception {
        try (var f = new Harness()) {
            var a = f.seed(value(), 0, List.of(), f.h.identity, status);
            f.check(f.update(value()), value(), Set.of(a));
        }
    }
    @ParameterizedTest @ValueSource(strings={"none","conflict","missing","opaque","restore","intent","invalid"})
    void preconditionsSignNothing(String mode) throws Exception {
        try (var f = new Harness()) {
            var desired = value(); var intent = ORDINARY;
            InitialTokenPublication.Status expected;
            if (!mode.equals("none")) f.seed(mode.equals("restore") ? edit(2,"","",42) : value(),0,List.of());
            switch(mode) {
                case "none" -> expected = NO_EXISTING_TOKEN;
                case "conflict" -> { f.seed(edit(1,"different","",42),1,List.of()); expected = CONFIRMATION_REQUIRED_CONFLICT; }
                case "missing" -> { f.unavailable.add(f.seed(value(),1,new ArrayList<>(f.context().graph().currentTokenHeads(TOKEN)))); expected = CONFIRMATION_REQUIRED_UNAVAILABLE; }
                case "opaque" -> { f.h.session.commitRecord(new KnownTokenNode(InitialDeviceAdvertisementTest.id(7),2,SemanticStatus.OPAQUE_ROUTABLE,TOKEN,List.of(),new SecurityBytes(f.h.identity.deviceId(),32),BigInteger.ZERO)); expected = CURRENT_OPAQUE_BLOCKED; }
                case "restore" -> expected = RESTORATION_INTENT_REQUIRED;
                case "intent" -> { intent = RESTORE; expected = INVALID_UPDATE_INTENT; }
                case "invalid" -> { desired = edit(3,"","",1); expected = INVALID_VALUE; }
                default -> throw new AssertionError();
            }
            f.blocked(expected,desired,intent);
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void restorationAllowsRetainedOrChangedCredential(boolean change) throws Exception {
        try(var f = new Harness()) {
            var a = f.seed(edit(2,"","",42),0,List.of());
            var desired = edit(1,"","",change?77:42);
            f.blocked(RESTORATION_INTENT_REQUIRED,desired,ORDINARY);
            f.check(f.update(desired,RESTORE,()->{}),desired,Set.of(a));
        }
    }
    @ParameterizedTest @CsvSource({"4,true,true","5,true,false","21,false,true","22,false,false","33,false,false"})
    void capacityKeepsEveryParent(int count, boolean maximum, boolean fits) throws Exception {
        try(var f=new Harness()) {
            for(int i=0;i<count;i++) f.seed(value(),i,List.of());
            var desired=maximum?new TokenValue(1,"i".repeat(256),"a".repeat(256),new TokenValue.Credential(3,8,0xffffffffL,new SecurityBytes(new byte[128],128))):value();
            var heads=f.context().graph().currentTokenHeads(TOKEN);
            assertEquals(count,heads.size());
            if(fits) f.check(f.update(desired),desired,heads); else f.blocked(FOLD_REQUIRED,desired,ORDINARY);
        }
    }
    @ParameterizedTest @ValueSource(strings={"frontier","discovery","unknown","blocked","unscoped","unavailable","revision","session","identity","root"})
    void staleNeverPublishesOrResigns(String change) throws Exception {
        try(var f=new Harness()) {
            var a=f.seed(value(),0,List.of()); int signs=f.h.keys.signs;
            var result=f.update(value(),ORDINARY,()->{
                switch(change) {
                    case "frontier" -> f.h.session.commitRecord(new KnownTokenNode(InitialDeviceAdvertisementTest.id(8),2,SemanticStatus.OPAQUE_ROUTABLE,TOKEN,List.of(),new SecurityBytes(f.h.identity.deviceId(),32),BigInteger.ZERO));
                    case "discovery" -> f.h.discovery=DiscoveryState.PROCESSING_INCOMPLETE;
                    case "unknown" -> f.h.session.markUnknown();
                    case "blocked" -> {f.h.memory.failAppend=true;f.h.session.commitRecord(InitialDeviceAdvertisementTest.node(f.h.identity,false,9));}
                    case "unscoped" -> f.h.session.commitRecord(new OpaqueUnscopedRecord(InitialDeviceAdvertisementTest.id(9),new SecurityBytes(new byte[1024],1024)));
                    case "unavailable" -> f.unavailable.add(a); // even without owner revision, view recheck catches this
                    case "revision" -> f.h.revision++;
                    case "identity" -> f.h.identity.close();
                    case "session" -> {try {f.h.session=SecurityMemorySession.open(f.h.memory);} catch(Exception e){throw new AssertionError(e);}}
                    case "root" -> {f.h.root[0]=1;f.h.revision++;}
                    default -> throw new AssertionError();
                }
            });
            assertEquals(OPERATION_STALE,result.status()); assertEquals(0,f.h.store.calls); assertEquals(signs+1,f.h.keys.signs);
        }
    }
    @ParameterizedTest @ValueSource(strings={"discovery","unknown","blocked","unscoped","identity","root","binding"})
    void readinessBeforeSigning(String change) throws Exception {
        try(var f=new Harness()) {
            f.seed(value(),0,List.of());
            switch(change) {
                case "discovery" -> f.h.discovery=DiscoveryState.PROCESSING_INCOMPLETE;
                case "unknown" -> f.h.session.markUnknown();
                case "blocked" -> {f.h.memory.failAppend=true;f.h.session.commitRecord(InitialDeviceAdvertisementTest.node(f.h.identity,false,9));}
                case "unscoped" -> f.h.session.commitRecord(new OpaqueUnscopedRecord(InitialDeviceAdvertisementTest.id(9),new SecurityBytes(new byte[1024],1024)));
                case "identity" -> f.h.identity.close();
                case "root","binding" -> f.h.root[0]=1;
            }
            int signs=f.h.keys.signs;
            assertNull(f.update(value()).receipt()); assertEquals(signs,f.h.keys.signs); assertEquals(0,f.h.store.calls);
        }
    }
    @ParameterizedTest @ValueSource(longs={0,1,Long.MAX_VALUE,Long.MIN_VALUE,-1})
    void exactUnsignedTime(long time) throws Exception {
        try(var f=new Harness()) {
            var a=f.seed(value(),-1,List.of());
            var result=TokenUpdatePublication.publish(f.h.root,f::context,f.h.identity,TOKEN,value(),time(time),ORDINARY,f.h.store,f.ads);
            f.check(result,value(),Set.of(a));
            assertEquals(new BigInteger(1,time(time)),((KnownTokenNode)f.h.session.knowledge().record(result.receipt().objectId())).authorTime());
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void publishedOrphanRecoversWithoutResigning(boolean graphFailure) throws Exception {
        try(var f=new Harness()) {
            var a=f.seed(value(),0,List.of());
            f.h.store.afterSnapshot=()->assertEquals(Set.of(a),f.context().graph().currentTokenHeads(TOKEN));
            if(graphFailure)f.h.memory.failAppend=true; else f.h.store.fault=FakeV1ObjectPublicationStore.Fault.AFTER_INSTALL;
            assertEquals(graphFailure?KNOWLEDGE_PERSISTENCE_FAILED:PUBLICATION_INCOMPLETE,f.update(edit(1,"new","",77)).status());
            assertEquals(Set.of(a),f.context().graph().currentTokenHeads(TOKEN));
            assertEquals(graphFailure,f.h.session.knowledge().knowledgePersistenceBlocked());
            int signs=f.h.keys.signs;
            f.h.memory.failAppend=false;f.h.session=SecurityMemorySession.open(f.h.memory);
            var source=new DiscoveryFixtures();f.h.store.snapshot().forEach(source::put);
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(source,f.h.root,f.h.session).discoveryState());
            var heads=f.context().graph().currentTokenHeads(TOKEN); assertEquals(1,heads.size());assertFalse(heads.contains(a));
            assertTrue(f.context().graph().ancestor(a,heads.iterator().next()));assertEquals(signs,f.h.keys.signs);
        }
    }
    @ParameterizedTest @ValueSource(booleans={false,true})
    void lateHiddenHistory(boolean equal) throws Exception {
        try(var f=new Harness()) {
            var a=f.seed(value(),0,List.of());var b=f.update(value()).receipt().objectId();byte[] immutable=f.h.store.get(b);
            var c=f.seed(equal?value():edit(1,"hidden","",77),-1,List.of(a));
            assertEquals(Set.of(b,c),f.context().graph().currentTokenHeads(TOKEN));
            if(equal)f.check(f.update(value()),value(),Set.of(b,c));
            else f.blocked(CONFIRMATION_REQUIRED_CONFLICT,value(),ORDINARY);
            assertArrayEquals(immutable,f.h.store.get(b));
        }
    }
    @Test void tokenIdEntropyOnlyUsedForInitialCreation() throws Exception {
        try(var f=new Harness()) {
            int[] draws={0};
            var initial=InitialTokenPublication.publish(f.h.root,f.h::context,f.h.identity,value(),time(0),f.h.store,List.of(),
                    bytes->{draws[0]++;Arrays.fill(bytes,(byte)0);},()->{});
            f.check(f.update(value()),value(),Set.of(initial.receipt().objectId()));
            assertEquals(1,draws[0]); // the update has no entropy dependency or TOKEN_ID generation path
        }
    }

    @Test void equalTombstonesReaffirmWithoutRestorationIntent() throws Exception {
        try (var f = new Harness()) {
            var tombstone = edit(2,"deleted","account",42);
            var a = f.seed(tombstone, 0, List.of());
            var b = f.seed(tombstone, -1, List.of());
            f.blocked(INVALID_UPDATE_INTENT, tombstone, RESTORE);
            f.check(f.update(tombstone), tombstone, Set.of(a,b));
        }
    }

    @Test void availablePeerDoesNotReplaceMissingCurrentValue() throws Exception {
        try (var f = new Harness()) {
            f.seed(value(), 0, List.of());
            f.unavailable.add(f.seed(value(), 1, List.of()));
            f.blocked(CONFIRMATION_REQUIRED_UNAVAILABLE, value(), ORDINARY);
        }
    }

    @ParameterizedTest @EnumSource(value = FakeDeviceKeyStore.SignFault.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    void signingFailureNeverPublishes(FakeDeviceKeyStore.SignFault fault) throws Exception {
        try (var f = new Harness()) {
            f.seed(value(),0,List.of()); int signs = f.h.keys.signs, appends = f.h.memory.appends;
            f.h.keys.signFault = fault;
            assertEquals(SIGNING_FAILED, f.update(value()).status());
            assertEquals(signs+1, f.h.keys.signs); assertEquals(0, f.h.store.calls); assertEquals(appends,f.h.memory.appends);
        }
    }

    @ParameterizedTest @EnumSource(value = FakeV1ObjectPublicationStore.Fault.class,
            names = {"NONE", "EXISTING_ACKNOWLEDGEMENT"}, mode = EnumSource.Mode.EXCLUDE)
    void failedPublicationDoesNotCommitOrRetry(FakeV1ObjectPublicationStore.Fault fault) throws Exception {
        try (var f = new Harness()) {
            var a = f.seed(value(),0,List.of()); int signs = f.h.keys.signs, appends = f.h.memory.appends;
            f.h.store.fault = fault;
            assertEquals(PUBLICATION_INCOMPLETE, f.update(value()).status());
            assertEquals(signs+1,f.h.keys.signs); assertEquals(1,f.h.store.calls); assertEquals(appends,f.h.memory.appends);
            assertEquals(Set.of(a),new GraphTopology(f.h.session.knowledge()).currentTokenHeads(TOKEN));
        }
    }

    @Test void storageOnlyInitialTokenIsNotExistingUntilDurablyDiscovered() throws Exception {
        try (var f = new Harness()) {
            var bytes = TokenWriter.signed(f.h.root,f.h.identity,TOKEN.bytes(),value(),time(0),List.of());
            var object = V1EnvelopeWriter.seal(f.h.root,bytes); f.h.store.seed(object.id(),object.bytes());
            f.blocked(NO_EXISTING_TOKEN,value(),ORDINARY);
            var source = new DiscoveryFixtures(); f.h.store.snapshot().forEach(source::put);
            assertEquals(DiscoveryState.READY,DiscoveryCoordinator.discover(source,f.h.root,f.h.session).discoveryState());
            f.check(f.update(value()),value(),Set.of(object.id()));
        }
    }

    @Test void arrivalOrderAndMissingAncestryUseActualMaximalHeads() throws Exception {
        try (var f = new Harness()) {
            var missing = InitialDeviceAdvertisementTest.id(79);
            var a = f.seed(value(),-1,List.of(missing));
            var b = f.seed(value(),1,List.of(a));
            var c = f.seed(value(),0,List.of(a));
            var orders = List.of(List.of(a,b,c),List.of(c,b,a),List.of(b,a,c));
            for (var order : orders) {
                var memory = DeviceIdentityLifecycleTest.established(DeviceIdentityLifecycleTest.binding(f.h.root));
                f.h.session = SecurityMemorySession.open(memory);
                for (var id : order) {
                    var assertion = AssertionValidator.validate(EnvelopeReader.open(id.filename(),f.h.store.get(id),f.h.root));
                    f.h.session.commit(AuthenticatedObservation.supported(assertion.object()));
                }
                assertEquals(ParentEdgeStatus.UNRESOLVED,new GraphTopology(f.h.session.knowledge()).edgeStatus(a,missing));
                // Missing ancestry alone is not missing current value (§29).
                f.check(f.update(value()),value(),Set.of(b,c));
            }
        }
    }

    @Test void exactCredentialAndUnicodeFieldsAreNotDisplayReconstructed() throws Exception {
        try (var f = new Harness()) {
            var a = f.seed(value(),0,List.of());
            var desired = new TokenValue(1,"e\u0301","\u00e9",new TokenValue.Credential(3,8,0xffffffffL,
                    new SecurityBytes(new byte[]{0,(byte)255,1},3)));
            f.check(f.update(desired),desired,Set.of(a));
        }
    }

    @Test void supportedFrontierChangeAfterSigningAbortsExactPlan() throws Exception {
        try (var f = new Harness()) {
            var a = f.seed(value(),0,List.of());
            var semantic = TokenWriter.signed(f.h.root,f.h.identity,TOKEN.bytes(),value(),time(99),List.of(a));
            var object = V1EnvelopeWriter.seal(f.h.root,semantic);
            var observation = AuthenticatedObservation.supported(AssertionValidator.validate(
                    EnvelopeReader.open(object.id().filename(),object.bytes(),f.h.root)).object());
            int signs = f.h.keys.signs;
            assertEquals(OPERATION_STALE,f.update(value(),ORDINARY,()->{
                f.h.store.seed(object.id(),object.bytes()); f.h.session.commit(observation);
            }).status());
            assertEquals(signs+1,f.h.keys.signs); assertEquals(0,f.h.store.calls);
            assertEquals(Set.of(object.id()),f.context().graph().currentTokenHeads(TOKEN));
        }
    }

    @Test void mismatchedLocalIdentityBindingCannotSign() throws Exception {
        try (var f = new Harness()) {
            f.seed(value(),0,List.of());
            var key = new DeviceProvenanceKey() {
                public byte[] vaultBinding() { return new byte[32]; }
                public byte[] publicKeyX963() { return f.h.identity.publicKeyX963(); }
                public byte[] signSha256Ecdsa(byte[] bytes) { throw new AssertionError("Must not sign"); }
                public void close() {}
            };
            try (var identity = DeviceIdentityResult.bound(DeviceIdentityResult.Status.AVAILABLE_BOUND,
                    key,key.vaultBinding(),key.publicKeyX963())) {
                int signs = f.h.keys.signs;
                assertEquals(DEVICE_IDENTITY_BINDING_MISMATCH,TokenUpdatePublication.publish(f.h.root,f::context,
                        identity,TOKEN,value(),time(0),ORDINARY,f.h.store,List.of()).status());
                assertEquals(signs,f.h.keys.signs); assertEquals(0,f.h.store.calls);
            }
        }
    }
}
