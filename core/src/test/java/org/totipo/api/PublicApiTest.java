package org.totipo.api;

import org.totipo.*;
import org.totipo.storage.nio.NioTotipo;
import org.totipo.testing.MemoryVault;
import org.totipo.format.ApplicationCausalFixture;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Predicate;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

class PublicApiTest {
    private static byte[] bootstrap;
    private MemoryVault store;
    private VaultSession session;
    @BeforeAll static void vaultTemplate() {
        var store = new MemoryVault();
        try (var session = store.create()) { bootstrap = store.bootstrap.clone(); assertNotNull(session.fingerprint()); }
    }
    @BeforeEach void open() { store = new MemoryVault(); store.bootstrap = bootstrap.clone(); session = store.open(); finished(session); }
    @AfterEach void close() { session.close(); }
    static VaultState finished(VaultSession session) { return awaitState(session, s -> s.observation() instanceof ObservationProgress.Finished); }
    static VaultState refresh(VaultSession session) {
        var old = session.state(); session.requestRefresh(); return awaitState(session, s -> s != old && s.observation() instanceof ObservationProgress.Finished);
    }
    static VaultState awaitState(VaultSession session, Predicate<VaultState> predicate) {
        var seen = new CompletableFuture<VaultState>();
        session.states().subscribe(new Flow.Subscriber<>() {
            Flow.Subscription subscription;
            @Override public void onSubscribe(Flow.Subscription value) { subscription = value; value.request(Long.MAX_VALUE); }
            @Override public void onNext(VaultState state) { if (predicate.test(state)) { seen.complete(state); subscription.cancel(); } }
            @Override public void onError(Throwable error) { seen.completeExceptionally(error); }
            @Override public void onComplete() { if (!seen.isDone()) seen.completeExceptionally(new AssertionError("Closed")); }
        });
        try { return seen.get(10, TimeUnit.SECONDS); } catch (Exception e) { throw new AssertionError(e); }
    }
    static SaveResult.Saved saved(SaveResult result) { return assertInstanceOf(SaveResult.Saved.class, result); }
    static TokenState token(VaultSession session, TokenId id) { return awaitState(session, s -> s.token(id).isPresent()).token(id).orElseThrow(); }
    TokenState create(String issuer) {
        try (var secret = NewSecret.copyOf("12345678901234567890".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
             var create = session.state().createToken()) {
            var result = saved(create.issuer(issuer).account("alice").digits(8).secret(secret).save());
            return token(session, result.tokenId());
        }
    }
    TokenState branch(TokenHead head, String issuer) {
        try (var update = session.state().update(head)) {
            saved(update.issuer(issuer).metadata(new ClientMetadata(Optional.of("branch-" + store.publications), Optional.empty())).save());
        }
        return refresh(session).token(head.tokenId()).orElseThrow();
    }
    static Stream<ClientMetadata> exactMetadataVariants() {
        return Stream.of(Optional.<String>empty(), Optional.of(""), Optional.of(" A\u0000\n e\u0301 😀 "))
                .flatMap(name -> Stream.of(Optional.<Long>empty(), Optional.of(0L), Optional.of(1L),
                        Optional.of(Long.MIN_VALUE), Optional.of(-1L)).map(time -> new ClientMetadata(name, time)));
    }
    @ParameterizedTest @MethodSource("exactMetadataVariants")
    void representedMetadataSurvivesRefreshDisappearanceReappearanceAndClose(ClientMetadata metadata) {
        SaveResult.Saved result;
        try (var secret = NewSecret.copyOf(new byte[]{1, 2, 3}); var create = session.state().createToken()) {
            result = saved(create.secret(secret).metadata(metadata).save());
        }
        var captured = refresh(session);
        var represented = captured.token(result.tokenId()).orElseThrow();
        var head = represented.heads().get(0);
        assertEquals(metadata, head.metadata());
        assertEquals(metadata, represented.alternatives().get(0).heads().get(0).metadata());
        assertEquals(metadata, refresh(session).token(result.tokenId()).orElseThrow().heads().get(0).metadata());
        var bytes = store.objects.remove(head.revision().hex());
        assertNotNull(bytes);
        assertTrue(refresh(session).token(result.tokenId()).isEmpty());
        assertEquals(metadata, captured.token(result.tokenId()).orElseThrow().heads().get(0).metadata());
        store.objects.put(head.revision().hex(), bytes);
        assertEquals(metadata, refresh(session).token(result.tokenId()).orElseThrow().heads().get(0).metadata());
        // An update authors a new object: absent operation metadata does not replace parent metadata.
        try (var update = session.state().update(head)) { saved(update.issuer("new assertion").save()); }
        assertEquals(ClientMetadata.empty(), refresh(session).token(result.tokenId()).orElseThrow().heads().get(0).metadata());
        session.close();
        assertEquals(metadata, head.metadata());
        assertEquals(metadata, represented.alternatives().get(0).heads().get(0).metadata());
    }
    @Test void capturedMergeAncestrySurvivesMissingIntermediateWithoutRepresentingIt() {
        var original = create("ancestor");
        var intermediate = branch(original.heads().get(0), "intermediate");
        var descendant = branch(intermediate.heads().get(0), "descendant");
        var captured = session.state();
        var intermediateHead = intermediate.heads().get(0);
        var descendantHead = descendant.heads().get(0);
        var metadata = new ClientMetadata(Optional.of("resolution e\u0301 😀"), Optional.of(-1L));
        // The merge captures C -> B -> A, including B which is already absent from public heads.
        try (var merge = captured.merge(original.id()).issuer("resolved").metadata(metadata)) {
            store.objects.remove(intermediateHead.revision().hex());
            store.objects.remove(descendantHead.revision().hex());
            var observed = refresh(session).token(original.id()).orElseThrow();
            assertEquals(original.heads(), observed.heads());
            assertEquals(List.of("ancestor"), observed.alternatives().stream().map(a -> a.descriptor().issuer()).toList());
            // A is contained in the captured frontier through the missing B; no new conflict exists.
            saved(merge.save());
        }
        var resolved = refresh(session).token(original.id()).orElseThrow();
        assertEquals(Set.of("resolved", "ancestor"), resolved.alternatives().stream()
                .map(a -> a.descriptor().issuer()).collect(java.util.stream.Collectors.toSet()));
        assertEquals(metadata, resolved.alternatives().stream().filter(a -> a.descriptor().issuer().equals("resolved"))
                .findFirst().orElseThrow().heads().get(0).metadata());
        assertEquals(descendantHead.metadata(), captured.token(original.id()).orElseThrow().heads().get(0).metadata());
        assertEquals(intermediateHead.metadata(), intermediate.alternatives().get(0).heads().get(0).metadata());
        // Current graph evaluation uses available objects only; retained merge ancestry creates no historical heads.
        assertTrue(resolved.heads().stream().noneMatch(h -> h.revision().equals(intermediateHead.revision())
                || h.revision().equals(descendantHead.revision())));
    }
    @Test void equalHeadsAndConflictResolutionKeepPerObjectMetadataThroughPartialRetryAndFold() {
        var original = create("base");
        var expected = new HashMap<RevisionId, ClientMetadata>();
        for (int i = 0; i < 7; i++) {
            var metadata = new ClientMetadata(Optional.of("branch-" + i), Optional.of(i == 0 ? -1L : i));
            try (var update = session.state().update(original.heads().get(0))) {
                var result = saved(update.issuer(i == 6 ? "conflict" : "equal").metadata(metadata).save());
                expected.put(result.revisions().get(0), metadata);
            }
            refresh(session);
        }
        var captured = session.state();
        var conflict = captured.token(original.id()).orElseThrow();
        assertTrue(conflict.hasConflict());
        assertEquals(6, conflict.alternatives().stream().filter(a -> a.descriptor().issuer().equals("equal"))
                .findFirst().orElseThrow().heads().size());
        conflict.heads().forEach(h -> assertEquals(expected.get(h.revision()), h.metadata()));
        var authored = new ClientMetadata(Optional.of(""), Optional.of(Long.MIN_VALUE));
        try (var merge = captured.merge(original.id()).issuer("resolved").metadata(authored)) {
            merge.secretChoices().get(0).alternatives().stream().flatMap(a -> a.heads().stream())
                    .forEach(h -> assertEquals(expected.get(h.revision()), h.metadata()));
            var lateMetadata = new ClientMetadata(Optional.of("late"), Optional.of(0L));
            SaveResult.Saved late;
            try (var update = captured.update(original.heads().get(0))) {
                late = saved(update.issuer("equal").metadata(lateMetadata).save());
            }
            expected.put(late.revisions().get(0), lateMetadata);
            var additional = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save());
            additional.latest().token(original.id()).orElseThrow().heads()
                    .forEach(h -> assertEquals(expected.get(h.revision()), h.metadata()));
            try (var partial = additional.resolution()) {
                store.publicationMode = 2;
                var uncertain = assertInstanceOf(SaveResult.PublicationUncertain.class, partial.save());
                store.publicationMode = 0;
                try (var retry = uncertain.retry()) {
                    assertEquals(2, saved(retry.retryPublication()).revisions().size()); // Seven parents require a fold.
                }
            }
            var result = refresh(session).token(original.id()).orElseThrow();
            assertEquals(2, result.heads().size());
            assertEquals(authored, result.alternatives().stream().filter(a -> a.descriptor().issuer().equals("resolved"))
                    .findFirst().orElseThrow().heads().get(0).metadata());
            assertEquals(lateMetadata, result.alternatives().stream().filter(a -> a.descriptor().issuer().equals("equal"))
                    .findFirst().orElseThrow().heads().get(0).metadata());
        }
        session.close();
        conflict.heads().forEach(h -> assertEquals(expected.get(h.revision()), h.metadata()));
    }
    @Test void nioCreateOpenAndLifecycle(@TempDir Path path) {
        VaultState old;
        TokenAlternative alternative;
        VaultFingerprint fingerprint;
        try (var nio = assertInstanceOf(CreateVaultResult.Created.class, NioTotipo.create(path, "pw".toCharArray())).session()) {
            assertNotNull(nio.state()); fingerprint = nio.fingerprint();
            try (var secret = NewSecret.copyOf(new byte[]{1, 2, 3}); var create = nio.state().createToken()) {
                var result = saved(create.secret(secret).save());
                old = awaitState(nio, s -> s.token(result.tokenId()).isPresent());
                alternative = old.tokens().get(0).alternatives().get(0);
                var newer = refresh(nio); assertNotSame(old, newer); assertEquals(old.tokens().size(), newer.tokens().size());
            }
        }
        assertEquals(1, old.tokens().size()); assertNotNull(alternative.descriptor()); assertNotNull(alternative.heads().get(0).metadata());
        assertThrows(SessionClosedException.class, old::createToken);
        assertThrows(SessionClosedException.class, () -> old.update(alternative));
        assertThrows(SessionClosedException.class, () -> old.merge(old.tokens().get(0).id()));
        assertThrows(SessionClosedException.class, () -> old.generateTotp(alternative, Instant.EPOCH));
        try (var reopened = assertInstanceOf(OpenResult.Opened.class, NioTotipo.open(path, "pw".toCharArray())).session()) {
            assertEquals(fingerprint, reopened.fingerprint()); assertEquals(1, finished(reopened).tokens().size());
        }
        assertInstanceOf(CreateVaultResult.AlreadyExists.class, NioTotipo.create(path, "pw".toCharArray()));
    }
    @Test void totpIsDeterministicAndLocalIncludingHistoricalTombstone() {
        var token = create("issuer"); var alternative = token.alternatives().get(0); var state = session.state();
        int scans = store.scans;
        var code = state.generateTotp(alternative, Instant.ofEpochSecond(59));
        assertEquals("94287082", code.code()); assertEquals(Instant.ofEpochSecond(30), code.validFrom());
        assertEquals(Instant.ofEpochSecond(60), code.validUntil()); assertEquals(scans, store.scans);
        try (var update = state.update(alternative)) { saved(update.status(TokenStatus.TOMBSTONED).save()); }
        var tombstone = refresh(session).token(token.id()).orElseThrow().alternatives().get(0);
        assertEquals(code, session.state().generateTotp(tombstone, Instant.ofEpochSecond(59)));
        assertEquals(code, session.state().generateTotp(alternative, Instant.ofEpochSecond(59)));
    }
    @Test void localOperationsCompleteWhileObservationIsBlocked() throws Exception {
        localOperationsWithBlockedProvider(false);
    }
    @Test void localOperationsCompleteWhilePublicationIsBlocked() throws Exception {
        localOperationsWithBlockedProvider(true);
    }
    private void localOperationsWithBlockedProvider(boolean publication) throws Exception {
        var token = create("known"); var state = session.state(); var alternative = token.alternatives().get(0);
        var executor = Executors.newFixedThreadPool(2);
        var entered = new CountDownLatch(1); var proceed = new CountDownLatch(1);
        Future<SaveResult> write = null;
        try (var editor = state.update(alternative); var writer = state.update(alternative)) {
            if (publication) {
                store.entered = entered; store.proceed = proceed;
                write = executor.submit(writer::save);
            } else {
                store.scanEntered = entered; store.scanProceed = proceed;
                session.requestRefresh();
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS));
            var code = executor.submit(() -> state.generateTotp(alternative, Instant.ofEpochSecond(59)));
            assertEquals("94287082", code.get(2, TimeUnit.SECONDS).code());
            executor.submit(() -> {
                try (var secret = NewSecret.copyOf(new byte[]{1, 2, 3}); var created = state.createToken()) {
                    editor.issuer("edited locally").account("account").digits(6).secret(secret);
                    created.issuer("also local").secret(secret);
                }
            }).get(2, TimeUnit.SECONDS);
            assertEquals(1, proceed.getCount());
            if (write != null) assertFalse(write.isDone());
            proceed.countDown();
            if (write != null) saved(write.get(5, TimeUnit.SECONDS));
            else refresh(session);
        } finally { proceed.countDown(); executor.shutdownNow(); }
    }
    @Test void projectionEqualitySurvivesStatesChangedHeadSetsAndClose() {
        var original = create("base"); var first = branch(original.heads().get(0), "X");
        var oldHead = first.heads().get(0); var oldAlternative = first.alternatives().get(0);
        var selectedHeads = new HashSet<>(List.of(oldHead)); var selectedValues = new HashMap<TokenAlternative, String>();
        selectedValues.put(oldAlternative, "selection");
        var refreshed = refresh(session).token(original.id()).orElseThrow();
        assertNotSame(oldHead, refreshed.heads().get(0)); assertEquals(oldHead, refreshed.heads().get(0));
        assertEquals(oldHead.hashCode(), refreshed.heads().get(0).hashCode());
        var second = branch(original.heads().get(0), "X"); var newer = second.alternatives().get(0);
        assertEquals(1, oldAlternative.heads().size()); assertEquals(2, newer.heads().size());
        assertEquals(oldAlternative, newer); assertEquals(oldAlternative.hashCode(), newer.hashCode());
        assertEquals("selection", selectedValues.get(newer));
        var sameHead = second.heads().stream().filter(h -> h.revision().equals(oldHead.revision())).findFirst().orElseThrow();
        assertTrue(selectedHeads.contains(sameHead));
        session.close(); assertEquals(oldAlternative, newer); assertEquals(oldHead, sameHead);
        assertEquals("selection", selectedValues.get(newer)); assertTrue(selectedHeads.contains(sameHead));
    }
    @Test void alternativeIdentityIncludesSecretTokenAndSession() {
        var original = create("same descriptor"); var old = original.alternatives().get(0);
        try (var secret = NewSecret.copyOf(new byte[]{9, 8, 7}); var update = session.state().update(old)) {
            saved(update.secret(secret).save());
        }
        var changed = refresh(session).token(original.id()).orElseThrow().alternatives().get(0);
        assertEquals(old.descriptor(), changed.descriptor()); assertNotEquals(old, changed);
        assertEquals(2, new HashSet<>(List.of(old, changed)).size());
        var otherToken = create("same descriptor").alternatives().get(0);
        assertEquals(old.descriptor(), otherToken.descriptor()); assertNotEquals(old, otherToken);
        try (var other = store.open()) {
            var equivalent = finished(other).token(original.id()).orElseThrow().alternatives().get(0);
            assertEquals(changed.descriptor(), equivalent.descriptor()); assertNotEquals(changed, equivalent);
            assertNotEquals(changed.heads().get(0), equivalent.heads().get(0));
            assertThrows(IllegalArgumentException.class, () -> session.state().update(equivalent));
        }
    }
    @Test void handleResultTypesExcludeImpossibleVariants() throws Exception {
        assertEquals(RetryResult.class, PublicationRetry.class.getMethod("retryPublication").getReturnType());
        assertEquals(PartialSaveResult.class, PartialResolution.class.getMethod("save").getReturnType());
        assertTrue(RetryResult.class.isSealed()); assertTrue(PartialSaveResult.class.isSealed());
        assertEquals(Set.of(SaveResult.Saved.class, SaveResult.PublicationUncertain.class),
                Set.of(RetryResult.class.getPermittedSubclasses()));
        assertEquals(Set.of(RetryResult.class, SaveResult.Failed.class),
                Set.of(PartialSaveResult.class.getPermittedSubclasses()));
        assertFalse(RetryResult.class.isAssignableFrom(SaveResult.Failed.class));
        assertFalse(PartialSaveResult.class.isAssignableFrom(SaveResult.AdditionalConflict.class));
    }
    @Test void oldHeadUsesExactlyOneParentWhileOldAlternativeUsesAllCurrentEqualHeads() {
        var original = create("base"); var h0 = original.heads().get(0);
        var first = branch(h0, "X"); var oldAlternative = first.alternatives().get(0); var h1 = first.heads().get(0);
        var second = branch(h0, "X"); assertEquals(2, second.heads().size()); assertEquals(1, second.alternatives().size());
        try (var update = session.state().update(h1)) { saved(update.issuer("Y").save()); }
        var third = refresh(session).token(original.id()).orElseThrow();
        assertEquals(2, third.heads().size()); assertEquals(2, third.alternatives().size());
        // Reintroduce a second X head; the old alternative still selects every current X assertion.
        branch(h0, "X2"); // Distinct metadata below gives another exact X assertion.
        try (var update = session.state().update(h0)) {
            saved(update.issuer("X").metadata(new ClientMetadata(Optional.of("second-X"), Optional.empty())).save());
        }
        var receiving = refresh(session);
        long equal = receiving.token(original.id()).orElseThrow().alternatives().stream()
                .filter(a -> a.descriptor().issuer().equals("X")).findFirst().orElseThrow().heads().size();
        assertEquals(2, equal);
        try (var update = receiving.update(oldAlternative)) { saved(update.issuer("Z").save()); }
        var result = refresh(session).token(original.id()).orElseThrow();
        assertTrue(result.alternatives().stream().noneMatch(a -> a.descriptor().issuer().equals("X")));
        assertEquals(Set.of("Y", "X2", "Z"), result.alternatives().stream().map(a -> a.descriptor().issuer()).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void historicalFallbackAndUnrelatedNewBranchNeverGateUpdate() {
        var original = create("old"); var old = original.alternatives().get(0);
        branch(original.heads().get(0), "new");
        try (var update = session.state().update(old)) { saved(update.issuer("historical").save()); }
        var result = refresh(session).token(original.id()).orElseThrow();
        assertEquals(Set.of("new", "historical"), result.alternatives().stream().map(a -> a.descriptor().issuer()).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void updateUsesReceivingStateEvenWhenSessionHasAdvanced() {
        var original = create("base"); branch(original.heads().get(0), "X");
        var receiving = session.state(); var selected = receiving.token(original.id()).orElseThrow().alternatives().get(0);
        branch(original.heads().get(0), "X");
        try (var update = receiving.update(selected)) { saved(update.issuer("Y").save()); }
        var result = refresh(session).token(original.id()).orElseThrow();
        assertEquals(2, result.heads().size()); assertEquals(2, result.alternatives().size());
    }
    @Test void selectedHistoricalMergeUsesCapturedBasisAndCanSupplyNewSecret() {
        var original = create("base"); var historical = original.alternatives().get(0);
        branch(original.heads().get(0), "current");
        try (var secret = NewSecret.copyOf(new byte[]{4, 5, 6}); var merge = session.state().merge(List.of(historical))) {
            saved(merge.issuer("historical resolution").secret(secret).save());
        }
        var result = refresh(session).token(original.id()).orElseThrow();
        assertEquals(2, result.heads().size()); assertEquals(2, result.competingValues().secret().groups().size());
    }
    @Test void referencesAreSessionScopedAndMixedTokensAreRejected() {
        var first = create("one"); var second = create("two");
        try (var other = store.open()) {
            var state = finished(other);
            assertThrows(IllegalArgumentException.class, () -> state.update(first.heads().get(0)));
            assertThrows(IllegalArgumentException.class, () -> state.update(first.alternatives().get(0)));
            assertThrows(IllegalArgumentException.class, () -> state.generateTotp(first.alternatives().get(0), Instant.EPOCH));
            assertThrows(IllegalArgumentException.class, () -> state.merge(first.alternatives()));
        }
        assertThrows(IllegalArgumentException.class, () -> session.state().merge(List.of(first.alternatives().get(0), second.alternatives().get(0))));
    }
    @Test void mergePrefillsAgreedFieldsAllowsNewValuesAndUsesCurrentFrontier() {
        var token = create("base"); var original = token.heads().get(0);
        branch(original, "X"); var conflict = branch(original, "Y");
        assertTrue(conflict.hasConflict()); assertTrue(conflict.competingValues().issuer().disagrees());
        assertFalse(conflict.competingValues().account().disagrees()); assertEquals(1, conflict.competingValues().secret().groups().size());
        try (var merge = session.state().merge(token.id())) {
            assertEquals(List.of("issuer"), merge.unresolvedFields());
            assertInstanceOf(SaveResult.Failed.class, merge.save());
            saved(merge.issuer("brand new").save());
        }
        var result = refresh(session).token(token.id()).orElseThrow();
        assertEquals(1, result.heads().size()); assertEquals("brand new", result.alternatives().get(0).descriptor().issuer());
        assertEquals("alice", result.alternatives().get(0).descriptor().account());
    }
    @Test void explicitPartialSelectionDoesNotTreatOmittedKnownHeadAsNew() {
        var original = create("base"); branch(original.heads().get(0), "X");
        var conflict = branch(original.heads().get(0), "Y");
        var chosen = conflict.alternatives().stream().filter(a -> a.descriptor().issuer().equals("X")).findFirst().orElseThrow();
        try (var merge = session.state().merge(List.of(chosen))) { saved(merge.issuer("partial").save()); }
        var result = refresh(session).token(original.id()).orElseThrow();
        assertEquals(Set.of("partial", "Y"), result.alternatives().stream().map(a -> a.descriptor().issuer()).collect(java.util.stream.Collectors.toSet()));
    }
    @Test void secretGroupsAndMergeOwnedChoices() {
        var original = create("base"); branch(original.heads().get(0), "X");
        try (var secret = NewSecret.copyOf(new byte[]{8, 9}); var update = session.state().update(original.heads().get(0))) {
            saved(update.issuer("Y").secret(secret).save());
        }
        var state = refresh(session); var token = state.token(original.id()).orElseThrow();
        assertEquals(2, token.competingValues().secret().groups().size());
        try (var a = state.merge(token.id()); var b = state.merge(token.id())) {
            assertTrue(a.unresolvedFields().contains("secret"));
            assertThrows(IllegalArgumentException.class, () -> b.secret(a.secretChoices().get(0)));
            saved(a.issuer("resolved").secret(a.secretChoices().get(0)).save());
        }
    }
    @Test void mergeNewConcurrentInformationReturnsIndependentPartialResolution() {
        additionalConflict(false);
    }
    @Test void mergeEqualValuedNewConcurrentHeadIsStillNewInformation() {
        additionalConflict(true);
    }
    private void additionalConflict(boolean equal) {
        var original = create("base"); branch(original.heads().get(0), "X");
        var state = session.state(); var merge = state.merge(original.id()).issuer("resolution");
        try (var update = state.update(original.heads().get(0))) {
            saved(update.issuer(equal ? "X" : "Y").metadata(new ClientMetadata(Optional.of("concurrent"), Optional.empty())).save());
        }
        int publications = store.publications;
        var conflict = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save());
        assertEquals(publications, store.publications); assertEquals(2, conflict.latest().token(original.id()).orElseThrow().heads().size());
        merge.close();
        try (var partial = conflict.resolution()) { saved(partial.save()); assertThrows(IllegalStateException.class, partial::save); }
        var finalToken = refresh(session).token(original.id()).orElseThrow();
        assertEquals(2, finalToken.heads().size()); assertTrue(finalToken.alternatives().stream().anyMatch(a -> a.descriptor().issuer().equals("resolution")));
    }
    @Test void mergeAdvancingDescendantIsAdditionalInformation() {
        var original = create("base"); var merge = session.state().merge(original.id());
        branch(original.heads().get(0), "advance");
        var result = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save()); result.resolution().close(); merge.close();
    }
    @Test void unavailableMergeObservationIsDefiniteNoWriteAndBuilderRemainsEditable() {
        var token = create("base"); var merge = session.state().merge(token.id()); int writes = store.publications;
        store.observationUnavailable = true;
        var result = assertInstanceOf(SaveResult.Failed.class, merge.save());
        assertEquals(SaveResult.Reason.OBSERVATION_UNAVAILABLE, result.reason()); assertEquals(writes, store.publications);
        store.observationUnavailable = false; saved(merge.issuer("retry").save()); merge.close();
    }
    @Test void resolvedAncestryAlreadyContainedInOriginalFrontierIsNotAdditional() {
        var original = create("base"); String ancestor = original.heads().get(0).revision().hex(); byte[] bytes = store.objects.get(ancestor);
        branch(original.heads().get(0), "child"); store.objects.remove(ancestor);
        var state = refresh(session); assertEquals(1, state.token(original.id()).orElseThrow().unresolvedReferences().size());
        var merge = state.merge(original.id()); store.objects.put(ancestor, bytes);
        saved(merge.save()); merge.close();
    }
    @Test void newlyResolvedValidCurrentObjectIsAdditional() {
        var original = create("base"); branch(original.heads().get(0), "X");
        var conflict = branch(original.heads().get(0), "Y");
        var y = conflict.alternatives().stream().filter(a -> a.descriptor().issuer().equals("Y")).findFirst().orElseThrow();
        String name = y.heads().get(0).revision().hex(); var bytes = store.objects.put(name, new byte[1024]);
        var state = refresh(session); assertFalse(state.diagnostics().isEmpty());
        var merge = state.merge(original.id()); store.objects.put(name, bytes);
        var result = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save()); result.resolution().close(); merge.close();
    }
    @Test void causalContainmentNeverTraversesAnotherLogicalToken() {
        var a = create("A"); var b = create("B");
        var foreignRevision = ApplicationCausalFixture.add(store, b.id(), a.heads().get(0));
        var foreignHead = refresh(session).token(b.id()).orElseThrow().heads().stream()
                .filter(h -> h.revision().equals(foreignRevision)).findFirst().orElseThrow();
        ApplicationCausalFixture.add(store, a.id(), foreignHead);
        String hidden = a.heads().get(0).revision().hex(); var bytes = store.objects.remove(hidden);
        var merge = refresh(session).merge(a.id()); store.objects.put(hidden, bytes);
        var conflict = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save());
        conflict.resolution().close(); merge.close();
    }
    @Test void uncertainRetryIsExactMonotonicAndIndependentOfBuilder() {
        var original = create("base"); var update = session.state().update(original.heads().get(0)).issuer("frozen");
        store.publicationMode = 2;
        var uncertain = assertInstanceOf(SaveResult.PublicationUncertain.class, update.save());
        assertThrows(IllegalStateException.class, () -> update.issuer("different")); update.close();
        int first = store.attemptedIds.size() - 1;
        store.publicationMode = 1;
        var again = assertInstanceOf(SaveResult.PublicationUncertain.class, uncertain.retry().retryPublication());
        uncertain.retry().close(); // The replacement handle is independent.
        store.publicationMode = 0;
        var result = saved(again.retry().retryPublication());
        assertEquals(store.attemptedIds.get(first), store.attemptedIds.get(first + 1));
        assertEquals(store.attemptedIds.get(first), store.attemptedIds.get(first + 2));
        assertArrayEquals(store.attemptedBytes.get(first), store.attemptedBytes.get(first + 2));
        assertEquals(result.revisions().get(0).hex(), store.attemptedIds.get(first));
        assertThrows(IllegalStateException.class, again.retry()::retryPublication);
    }
    @Test void closedHandlesAndSessionInvalidateCapabilities() {
        var token = create("base"); store.publicationMode = 2;
        var update = session.state().update(token.heads().get(0));
        var retry = assertInstanceOf(SaveResult.PublicationUncertain.class, update.save()).retry();
        retry.close(); assertThrows(IllegalStateException.class, retry::retryPublication); update.close();
        var second = session.state().update(token.heads().get(0));
        var outstanding = assertInstanceOf(SaveResult.PublicationUncertain.class, second.save()).retry();
        session.close(); assertThrows(SessionClosedException.class, outstanding::retryPublication);
        assertThrows(SessionClosedException.class, () -> session.changePassword("password".toCharArray(), "new".toCharArray()));
    }
    @Test void secretIngressIsDefensiveRedactedAndBuilderOwnsCopy() {
        byte[] bytes = {1, 2, 3}; var secret = NewSecret.copyOf(bytes); bytes[0] = 9;
        assertArrayEquals(new byte[]{1, 2, 3}, secret.copy()); assertEquals("NewSecret[redacted]", secret.toString());
        var create = session.state().createToken().secret(secret); secret.close();
        assertThrows(IllegalStateException.class, secret::copy); saved(create.save()); create.close();
    }
    @Test void initialCreationAndOpenTaxonomies() {
        var empty = new MemoryVault(); assertInstanceOf(OpenResult.Absent.class, empty.openResult(new char[0]));
        empty.readUnavailable = true; assertInstanceOf(OpenResult.Unavailable.class, empty.openResult(new char[0]));
        empty.readUnavailable = false; empty.bootstrap = new byte[]{1}; assertInstanceOf(OpenResult.InvalidVault.class, empty.openResult(new char[0]));
        assertInstanceOf(OpenResult.AuthenticationFailed.class, store.openResult("not-password".toCharArray()));
        assertInstanceOf(CreateVaultResult.AlreadyExists.class, store.createResult(new char[0]));
        empty.bootstrap = null; empty.failBeforeStage = true; assertInstanceOf(CreateVaultResult.Failed.class, empty.createResult(new char[0]));
        empty.failBeforeStage = false; empty.failReplacement = true; assertInstanceOf(CreateVaultResult.Uncertain.class, empty.createResult(new char[0]));
    }
    private static final class Probe implements Flow.Subscriber<VaultState> {
        Flow.Subscription subscription;
        final BlockingQueue<VaultState> received = new LinkedBlockingQueue<>();
        final CompletableFuture<Void> completion = new CompletableFuture<>();
        final List<VaultState> history = new CopyOnWriteArrayList<>();
        final java.util.concurrent.atomic.AtomicInteger terminalSignals = new java.util.concurrent.atomic.AtomicInteger();
        volatile boolean subscribed, terminal;
        @Override public void onSubscribe(Flow.Subscription subscription) {
            assertFalse(subscribed); subscribed = true; this.subscription = subscription;
        }
        @Override public void onNext(VaultState state) {
            assertTrue(subscribed); assertFalse(terminal); history.add(state); received.add(state);
        }
        @Override public void onError(Throwable error) { terminalSignals.incrementAndGet(); terminal = true; completion.completeExceptionally(error); }
        @Override public void onComplete() { assertTrue(subscribed); terminalSignals.incrementAndGet(); terminal = true; completion.complete(null); }
        VaultState next() throws Exception { var state = received.poll(5, TimeUnit.SECONDS); assertNotNull(state); return state; }
    }
    @Test void replayLatestCoalescesWithoutDemandAndSubscribersAreIndependent() throws Exception {
        var a = new Probe(); var b = new Probe(); session.states().subscribe(a); session.states().subscribe(b);
        assertTrue(a.subscribed); assertTrue(b.subscribed); assertTrue(a.received.isEmpty());
        var first = refresh(session); var latest = refresh(session); assertNotSame(first, latest);
        a.subscription.request(1); assertSame(latest, a.next()); assertTrue(b.received.isEmpty());
        var next = refresh(session); b.subscription.request(1); assertSame(next, b.next()); assertTrue(a.received.isEmpty());
        var newest = refresh(session); a.subscription.request(1); b.subscription.request(1);
        assertSame(newest, a.next()); assertSame(newest, b.next());
        assertEquals(List.of(latest, newest), a.history); assertEquals(List.of(next, newest), b.history);
        session.close(); a.completion.get(5, TimeUnit.SECONDS); b.completion.get(5, TimeUnit.SECONDS);
        a.subscription.request(Long.MAX_VALUE); assertTrue(a.received.isEmpty());
        var afterClose = new Probe(); session.states().subscribe(afterClose); afterClose.subscription.request(1);
        afterClose.completion.get(5, TimeUnit.SECONDS); assertTrue(afterClose.received.isEmpty());
    }
    @Test void streamOrdersEmissionsAndObservationDiagnosticsDoNotTerminate() throws Exception {
        var probe = new Probe(); session.states().subscribe(probe); probe.subscription.request(Long.MAX_VALUE);
        assertSame(session.state(), probe.next());
        for (int i = 0; i < 6; i++) { var state = refresh(session); assertSame(state, probe.next()); }
        store.observationUnavailable = true;
        var failedObservation = refresh(session); assertFalse(failedObservation.diagnostics().isEmpty());
        assertSame(failedObservation, probe.next()); assertFalse(probe.terminal);
        store.observationUnavailable = false;
        assertSame(refresh(session), probe.next());
        assertEquals(probe.history.size(), new HashSet<>(probe.history).size());
        session.close(); probe.completion.get(5, TimeUnit.SECONDS);
        assertTrue(probe.received.isEmpty());
    }
    @Test void nonPositiveDemandTerminatesOnlyThatSubscriber() throws Exception {
        var invalid = new Probe(); var valid = new Probe(); session.states().subscribe(invalid); session.states().subscribe(valid);
        invalid.subscription.request(0);
        var error = assertThrows(ExecutionException.class, () -> invalid.completion.get(5, TimeUnit.SECONDS));
        assertInstanceOf(IllegalArgumentException.class, error.getCause());
        valid.subscription.request(1); assertSame(session.state(), valid.next());
    }
    @Test void closeFromOnNextCompletesWithoutWaitingForItsOwnCallback() throws Exception {
        var events = new CopyOnWriteArrayList<String>(); var completed = new CompletableFuture<Void>();
        session.states().subscribe(new Flow.Subscriber<>() {
            @Override public void onSubscribe(Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
            @Override public void onNext(VaultState state) {
                events.add("next"); session.close(); events.add("close returned");
            }
            @Override public void onError(Throwable error) { events.add("error"); completed.completeExceptionally(error); }
            @Override public void onComplete() { events.add("complete"); completed.complete(null); }
        });
        completed.get(5, TimeUnit.SECONDS);
        assertEquals(List.of("next", "close returned", "complete"), events);
        assertTrue(store.publicationClosed); assertTrue(store.bootstrapClosed);
        assertThrows(SessionClosedException.class, () -> session.state().createToken());
        assertThrows(SessionClosedException.class, session::requestRefresh);
        session.close(); assertEquals(List.of("next", "close returned", "complete"), events);
    }
    @Test void fatalObservationErrorsCurrentAndLateSubscribersExactlyOnce() throws Exception {
        var probe = new Probe(); session.states().subscribe(probe); probe.subscription.request(Long.MAX_VALUE); probe.next();
        var cause = new IllegalStateException("Fatal observation fixture"); store.fatalObservation = cause;
        session.requestRefresh();
        var failure = assertThrows(ExecutionException.class, () -> probe.completion.get(5, TimeUnit.SECONDS));
        assertSame(cause, failure.getCause()); assertEquals(1, probe.terminalSignals.get());
        assertTrue(store.publicationClosed); assertTrue(store.bootstrapClosed);
        assertThrows(SessionClosedException.class, session::requestRefresh);
        session.close(); probe.subscription.request(Long.MAX_VALUE); assertTrue(probe.received.isEmpty());
        var late = new Probe(); session.states().subscribe(late); late.subscription.request(1);
        var lateFailure = assertThrows(ExecutionException.class, () -> late.completion.get(5, TimeUnit.SECONDS));
        assertSame(cause, lateFailure.getCause()); assertEquals(1, late.terminalSignals.get()); assertTrue(late.received.isEmpty());
    }
    @Test void fatalMergeObservationAlsoTerminatesTheSessionWithItsCause() throws Exception {
        var token = create("base"); var merge = session.state().merge(token.id());
        var probe = new Probe(); session.states().subscribe(probe);
        var cause = new IllegalStateException("Fatal merge observation fixture"); store.fatalObservation = cause;
        assertSame(cause, assertThrows(IllegalStateException.class, merge::save));
        var failure = assertThrows(ExecutionException.class, () -> probe.completion.get(5, TimeUnit.SECONDS));
        assertSame(cause, failure.getCause()); assertEquals(1, probe.terminalSignals.get());
        assertTrue(store.publicationClosed); assertTrue(store.bootstrapClosed); merge.close();
    }
    @Test void explicitCloseWinningFatalRaceKeepsCompletionForAllSubscribers() throws Exception {
        var probe = new Probe(); session.states().subscribe(probe);
        store.scanEntered = new CountDownLatch(1); store.scanProceed = new CountDownLatch(1);
        var executor = Executors.newSingleThreadExecutor();
        try {
            session.requestRefresh(); assertTrue(store.scanEntered.await(5, TimeUnit.SECONDS));
            var closing = executor.submit(session::close); awaitClosing(session);
            store.fatalObservation = new IllegalStateException("Failure after explicit close began");
            store.scanProceed.countDown(); closing.get(5, TimeUnit.SECONDS);
            probe.completion.get(5, TimeUnit.SECONDS); assertEquals(1, probe.terminalSignals.get());
            var late = new Probe(); session.states().subscribe(late); late.completion.get(5, TimeUnit.SECONDS);
            assertEquals(1, late.terminalSignals.get()); assertTrue(late.received.isEmpty());
        } finally { store.scanProceed.countDown(); executor.shutdownNow(); }
    }
    @Test void closeWaitsForPotentiallyPersistedWriteAndPreservesSavedOrUncertain() throws Exception {
        for (int mode : new int[]{0, 2}) {
            var memory = new MemoryVault(); memory.bootstrap = bootstrap.clone();
            var live = memory.open(); finished(live);
            var executor = Executors.newFixedThreadPool(2);
            try (var secret = NewSecret.copyOf(new byte[]{1})) {
                var builder = live.state().createToken().secret(secret);
                memory.publicationMode = mode; memory.entered = new CountDownLatch(1); memory.proceed = new CountDownLatch(1);
                var save = executor.submit(builder::save); assertTrue(memory.entered.await(5, TimeUnit.SECONDS));
                var closing = executor.submit(live::close);
                awaitClosing(live);
                assertFalse(closing.isDone()); assertNotNull(live.state());
                memory.proceed.countDown();
                var result = save.get(5, TimeUnit.SECONDS); closing.get(5, TimeUnit.SECONDS);
                if (mode == 0) saved(result);
                else {
                    var uncertain = assertInstanceOf(SaveResult.PublicationUncertain.class, result);
                    assertThrows(SessionClosedException.class, uncertain.retry()::retryPublication);
                }
                builder.close();
            } finally { memory.proceed.countDown(); live.close(); executor.shutdownNow(); }
        }
    }
    private static void awaitClosing(VaultSession live) {
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            while (true) {
                try { live.requestRefresh(); }
                catch (SessionClosedException expected) { return; }
                Thread.onSpinWait();
            }
        });
    }
    @Test void closeDuringMergeObservationCanCancelWithDefiniteNoWrite() throws Exception {
        var token = create("base"); var merge = session.state().merge(token.id()); int writes = store.publications;
        store.scanEntered = new CountDownLatch(1); store.scanProceed = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var save = executor.submit(merge::save); assertTrue(store.scanEntered.await(5, TimeUnit.SECONDS));
            var close = executor.submit(session::close); awaitClosing(session); store.scanProceed.countDown();
            var failed = assertInstanceOf(SaveResult.Failed.class, save.get(5, TimeUnit.SECONDS));
            assertEquals(SaveResult.Reason.SESSION_CLOSING, failed.reason()); assertEquals(writes, store.publications);
            close.get(5, TimeUnit.SECONDS);
        } finally { store.scanProceed.countDown(); executor.shutdownNow(); merge.close(); }
    }
    @Test void partialHandleCanBeAbandonedOrInvalidatedBySessionClose() {
        var token = create("base"); var merge = session.state().merge(token.id()); branch(token.heads().get(0), "new");
        var partial = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save()).resolution(); merge.close();
        partial.close(); assertThrows(IllegalStateException.class, partial::save);
        var another = session.state().merge(token.id()); branch(token.heads().get(0), "another");
        var outstanding = assertInstanceOf(SaveResult.AdditionalConflict.class, another.save()).resolution(); another.close();
        session.close(); assertThrows(SessionClosedException.class, outstanding::save);
    }
    @Test void partialSaveFreezesSecretAndCanBecomeUncertainWithoutAnotherSemanticGate() {
        var token = create("base"); var merge = session.state().merge(token.id()).issuer("resolved");
        try (var secret = NewSecret.copyOf(new byte[]{6, 7, 8})) { merge.secret(secret); }
        branch(token.heads().get(0), "new");
        var partial = assertInstanceOf(SaveResult.AdditionalConflict.class, merge.save()).resolution(); merge.close();
        branch(token.heads().get(0), "newer");
        store.publicationMode = 2;
        var retry = assertInstanceOf(SaveResult.PublicationUncertain.class, partial.save()).retry(); partial.close();
        store.publicationMode = 0; saved(retry.retryPublication());
        assertEquals(3, refresh(session).token(token.id()).orElseThrow().heads().size());
    }
    @Test void closeDuringRetryNeverDowngradesPriorUncertainty() throws Exception {
        var token = create("base"); store.publicationMode = 2;
        var update = session.state().update(token.heads().get(0)).issuer("frozen");
        var retry = assertInstanceOf(SaveResult.PublicationUncertain.class, update.save()).retry(); update.close();
        store.publicationMode = 1; store.entered = new CountDownLatch(1); store.proceed = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var save = executor.submit(retry::retryPublication); assertTrue(store.entered.await(5, TimeUnit.SECONDS));
            var close = executor.submit(session::close); awaitClosing(session); store.proceed.countDown();
            assertInstanceOf(SaveResult.PublicationUncertain.class, save.get(5, TimeUnit.SECONDS)); close.get(5, TimeUnit.SECONDS);
        } finally { store.proceed.countDown(); executor.shutdownNow(); }
    }
    @Test void definitePrepublicationFailureRemainsEditableAndClosedBuilderRejectsUse() {
        var create = session.state().createToken(); int attempts = store.publications;
        assertInstanceOf(SaveResult.Failed.class, create.save()); assertEquals(attempts, store.publications);
        try (var secret = NewSecret.copyOf(new byte[]{1})) { saved(create.secret(secret).save()); }
        assertThrows(IllegalStateException.class, create::save); create.close();
        assertThrows(IllegalStateException.class, () -> create.issuer("no"));
    }
    @Test void exactRetryPreservesEveryStageOfAFold() {
        var token = create("base");
        for (int i = 0; i < 6; i++) branch(token.heads().get(0), "branch" + i);
        var state = refresh(session); assertEquals(6, state.token(token.id()).orElseThrow().heads().size());
        var merge = state.merge(token.id()).issuer("resolved"); store.publicationMode = 2;
        int offset = store.attemptedIds.size();
        var retry = assertInstanceOf(SaveResult.PublicationUncertain.class, merge.save()).retry(); merge.close();
        store.publicationMode = 0;
        var result = saved(retry.retryPublication()); assertTrue(result.revisions().size() > 1);
        assertEquals(store.attemptedIds.get(offset), store.attemptedIds.get(offset + 1));
        assertArrayEquals(store.attemptedBytes.get(offset), store.attemptedBytes.get(offset + 1));
        assertEquals(1, refresh(session).token(token.id()).orElseThrow().heads().size());
    }
    @Test void passwordAuthenticationStaleFailureUncertaintyAndReopen() {
        assertEquals(PasswordChangeResult.AUTHENTICATION_FAILED, session.changePassword("wrong".toCharArray(), "new".toCharArray()));
        store.readUnavailable = true; assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        store.readUnavailable = false; store.failBeforeStage = true;
        assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        store.failBeforeStage = false; store.staleReplacement = true;
        assertEquals(PasswordChangeResult.STALE, session.changePassword("password".toCharArray(), "new".toCharArray()));
        store.bootstrap = bootstrap.clone(); store.staleReplacement = false; store.failReplacement = true;
        assertEquals(PasswordChangeResult.UNCERTAIN, session.changePassword("password".toCharArray(), "new".toCharArray()));
        try (var reopened = assertInstanceOf(OpenResult.Opened.class, store.openResult("new".toCharArray())).session()) {
            assertEquals(session.fingerprint(), reopened.fingerprint());
        }
    }
    @Test void passwordChangeRejectsTrailingOrShortBaseWithBoundedRead() {
        // The pinned r18 record is 87 bytes; 88 is only the lookahead bound.
        assertEquals(87, bootstrap.length);
        store.bootstrapReadLimit = bootstrap.length + 1;
        for (int size : new int[]{bootstrap.length + 1, bootstrap.length + 4096, bootstrap.length - 1}) {
            store.bootstrap = Arrays.copyOf(bootstrap, size); store.maxBootstrapRead = 0;
            byte[] before = store.bootstrap.clone();
            assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
            assertEquals(0, store.replacementAttempts); assertArrayEquals(before, store.bootstrap);
            assertEquals(Math.min(size, bootstrap.length + 1), store.maxBootstrapRead);
        }
    }
    @Test void passwordChangeRejectsCanonicalTrailingDataAddedBeforeComparison() {
        store.bootstrapReadLimit = bootstrap.length + 1;
        store.afterReplacementStage = () -> store.bootstrap = Arrays.copyOf(store.bootstrap, bootstrap.length + 4096);
        assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        assertEquals(0, store.replacementAttempts); assertEquals(bootstrap.length + 4096, store.bootstrap.length);
        assertEquals(bootstrap.length + 1, store.maxBootstrapRead);
    }
    @Test void stagedReplacementWithTrailingDataIsRejectedBeforeReplacement() {
        store.bootstrapReadLimit = bootstrap.length + 1;
        for (int trailing : new int[]{1, 4096}) {
            store.stagedTrailingBytes = trailing;
            assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
            assertEquals(0, store.replacementAttempts); assertArrayEquals(bootstrap, store.bootstrap);
            assertEquals(bootstrap.length + 1, store.maxBootstrapRead);
        }
    }
    @Test void stagedInitialBootstrapWithTrailingDataIsRejectedBeforeInstallation() {
        for (int trailing : new int[]{1, 4096}) {
            var empty = new MemoryVault(); empty.stagedTrailingBytes = trailing; empty.bootstrapReadLimit = bootstrap.length + 1;
            assertInstanceOf(CreateVaultResult.Failed.class, empty.createResult("password".toCharArray()));
            assertNull(empty.bootstrap); assertEquals(0, empty.initialInstallAttempts);
            assertEquals(bootstrap.length + 1, empty.maxBootstrapRead);
        }
    }
    @Test void canonicalDisappearanceBeforeReplacementIsFailedNotStale() {
        store.afterReplacementStage = () -> store.bootstrap = null;
        assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        assertEquals(0, store.replacementAttempts); assertNull(store.bootstrap);
    }
    @Test void unusableCurrentObservationFailsWhileExactChangedBytesAreStale() {
        store.afterReplacementStage = () -> store.readUnavailable = true;
        assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        store.readUnavailable = false;
        store.afterReplacementStage = () -> store.bootstrap = Arrays.copyOf(bootstrap, bootstrap.length - 1);
        assertEquals(PasswordChangeResult.FAILED, session.changePassword("password".toCharArray(), "new".toCharArray()));
        store.bootstrap = bootstrap.clone();
        store.afterReplacementStage = () -> store.bootstrap[store.bootstrap.length - 1] ^= 1;
        assertEquals(PasswordChangeResult.STALE, session.changePassword("password".toCharArray(), "new".toCharArray()));
        assertEquals(0, store.replacementAttempts);
    }
    @Test void exactProtocolLengthCreationAndPasswordReplacementRemainSuccessful() {
        var empty = new MemoryVault(); empty.bootstrapReadLimit = bootstrap.length + 1;
        try (var created = empty.create()) {
            assertEquals(bootstrap.length, empty.bootstrap.length); assertEquals(1, empty.initialInstallAttempts);
            assertEquals(PasswordChangeResult.CHANGED, created.changePassword("password".toCharArray(), "new".toCharArray()));
            assertEquals(bootstrap.length, empty.bootstrap.length); assertEquals(1, empty.replacementAttempts);
            assertEquals(bootstrap.length, empty.maxBootstrapRead);
            try (var reopened = assertInstanceOf(OpenResult.Opened.class, empty.openResult("new".toCharArray())).session()) {
                assertEquals(created.fingerprint(), reopened.fingerprint());
            }
            assertInstanceOf(OpenResult.AuthenticationFailed.class, empty.openResult("password".toCharArray()));
        }
    }
    @Test void nioOpenIsReadOnlyWithNoObjectNamespace(@TempDir Path path) throws Exception {
        Files.write(path.resolve("vault"), bootstrap);
        assertFalse(Files.exists(path.resolve("objects-v1")));
        assertNioOpenUnchanged(path, "password", OpenResult.Opened.class);
        assertNioOpenUnchanged(path, "wrong", OpenResult.AuthenticationFailed.class);
        assertFalse(Files.exists(path.resolve("objects-v1")));
        Files.write(path.resolve("vault"), Arrays.copyOf(bootstrap, bootstrap.length + 1));
        assertNioOpenUnchanged(path, "password", OpenResult.InvalidVault.class);
        Files.delete(path.resolve("vault"));
        assertNioOpenUnchanged(path, "password", OpenResult.Absent.class);
        Files.createDirectory(path.resolve("vault"));
        assertNioOpenUnchanged(path, "password", OpenResult.Unavailable.class);
        assertFalse(Files.exists(path.resolve("objects-v1")));
    }
    @Test void nioOpenDoesNotRepairExistingProtocolFiles(@TempDir Path path) throws Exception {
        Files.write(path.resolve("vault"), bootstrap);
        Files.createDirectory(path.resolve("objects-v1"));
        Files.write(path.resolve("objects-v1").resolve("ab".repeat(32)), new byte[]{1, 2, 3});
        assertNioOpenUnchanged(path, "password", OpenResult.Opened.class);
        assertNioOpenUnchanged(path, "wrong", OpenResult.AuthenticationFailed.class);
    }
    private static void assertNioOpenUnchanged(Path path, String password, Class<? extends OpenResult> expected) throws Exception {
        var before = diskSnapshot(path);
        var result = NioTotipo.open(path, password.toCharArray());
        assertInstanceOf(expected, result);
        if (result instanceof OpenResult.Opened opened) {
            try (var live = opened.session()) { finished(live); }
        }
        assertEquals(before, diskSnapshot(path));
    }
    private record DiskEntry(boolean directory, Object fileKey, java.nio.file.attribute.FileTime modified, String bytes) { }
    private static Map<String, DiskEntry> diskSnapshot(Path path) throws Exception {
        var entries = new HashMap<String, DiskEntry>();
        try (var paths = Files.walk(path)) {
            for (var entry : paths.toList()) {
                var attributes = Files.readAttributes(entry, java.nio.file.attribute.BasicFileAttributes.class);
                entries.put(path.relativize(entry).toString(), new DiskEntry(attributes.isDirectory(), attributes.fileKey(),
                        attributes.lastModifiedTime(), attributes.isDirectory() ? "" : HexFormat.of().formatHex(Files.readAllBytes(entry))));
            }
        }
        return entries;
    }
}
