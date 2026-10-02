package org.totipo.format;

import org.totipo.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Supplier;

/** Session owner and adapter. No protocol-bearing object escapes through application projections. */
final class ApplicationSession implements VaultSession {
    private final byte[] root;
    private final VaultFingerprint fingerprint;
    private final VaultBootstrapReplacementStorage bootstrap;
    private final DiscoverySource discovery;
    private final V1ObjectPublicationStore publication;
    // Lock order is provider gate -> local. Never wait for provider I/O holding local.
    private final ReentrantLock gate = new ReentrantLock();
    private final ReentrantLock local = new ReentrantLock();
    private final ExecutorService observer = Executors.newSingleThreadExecutor(r -> {
        var thread = new Thread(r, "totipo-observation"); thread.setDaemon(true); return thread;
    });
    private final AtomicBoolean refresh = new AtomicBoolean();
    private final Set<AutoCloseable> owned = new HashSet<>();
    private final Map<Long, TokenValue> values = new HashMap<>();
    private final Map<TokenValue, Long> valueIds = new HashMap<>();
    private long nextValue, nextState;
    private volatile boolean closing;
    private Throwable terminationCause; // Guarded by local; first lifecycle termination wins.
    private boolean closed; // Guarded by gate.
    private volatile State current;
    private final ApplicationStates publisher;
    private record CausalFact(org.totipo.TokenId token, List<ObjectId> parents) { }
    private Map<ObjectId, CausalFact> ancestry = Map.of();

    ApplicationSession(byte[] root, VaultBootstrapReplacementStorage bootstrap, DiscoverySource discovery,
                       V1ObjectPublicationStore publication) {
        this.root = root.clone(); this.bootstrap = bootstrap; this.discovery = discovery; this.publication = publication;
        fingerprint = new VaultFingerprint(HexFormat.of().formatHex(CryptoSupport.vaultFingerprint(root)));
        current = new State(this, nextState++, new ObservationProgress.Enumerating(0), List.of(), List.of());
        publisher = new ApplicationStates(current);
        requestRefresh();
    }
    @Override public VaultFingerprint fingerprint() { return fingerprint; }
    @Override public VaultState state() { return publisher.current(); }
    @Override public Flow.Publisher<VaultState> states() { return publisher; }
    void requireOpen() { if (closing) throw new SessionClosedException(); }
    <T> T access(Supplier<T> action) {
        requireOpen(); local.lock();
        try { requireOpen(); return action.get(); } finally { local.unlock(); }
    }
    private <T> T providerAccess(Supplier<T> action) {
        requireOpen(); gate.lock();
        try { requireOpen(); return action.get(); } finally { gate.unlock(); }
    }
    @Override public void requestRefresh() {
        requireOpen();
        if (!refresh.compareAndSet(false, true)) return;
        try {
            observer.execute(() -> {
                gate.lock();
                try {
                    refresh.set(false);
                    if (!closing) observe();
                } catch (RuntimeException | Error fatal) {
                    terminate(fatal);
                } finally { gate.unlock(); }
            });
        } catch (RejectedExecutionException closed) { refresh.set(false); requireOpen(); throw closed; }
    }
    private void emit(State next) { current = next; publisher.emit(next); }
    /** Returns whether enumeration and every candidate read completed sufficiently for a merge check. */
    boolean observe() {
        try { return observePass(); }
        catch (RuntimeException | Error fatal) { terminate(fatal); throw fatal; }
    }
    private boolean observePass() {
        TokenStoreObservation observation;
        try { observation = TokenStoreReader.read(discovery, root); }
        catch (SecurityException | UnsupportedOperationException unavailable) {
            observation = new TokenStoreObservation(List.of(), List.of(),
                    List.of(DiscoverySource.SnapshotIssue.ENUMERATION_UNAVAILABLE));
        }
        var diagnostics = new ArrayList<VaultDiagnostic>();
        observation.snapshotDiagnostics().forEach(d -> diagnostics.add(new VaultDiagnostic(d.name())));
        observation.candidateDiagnostics().forEach(d -> diagnostics.add(new VaultDiagnostic(d.reason().name())));
        var graph = TokenGraph.evaluate(observation.validatedTokens());
        local.lock();
        try {
            graph.contradictoryObjectIds().forEach(id -> diagnostics.add(new VaultDiagnostic("CONTRADICTORY_OBJECT")));
            var links = new HashMap<ObjectId, CausalFact>();
            var tokens = new ArrayList<TokenState>();
            // Every validated value is retained by the session so historical references remain usable.
            // Equality-map entries own their secrets; redundant parsed copies are wiped after projection.
            var redundant = new ArrayList<SecurityBytes>();
            for (var object : observation.validatedTokens()) {
                var value = object.token().value();
                Long id = valueIds.get(value);
                if (id == null) { id = ++nextValue; valueIds.put(value, id); values.put(id, value); }
                else if (values.get(id) != value) redundant.add(value.credential().secret());
            }
            for (var entry : graph.perToken().entrySet()) {
                var id = publicId(entry.getKey());
                var view = entry.getValue();
                view.objects().forEach(o -> links.put(o.objectId(), new CausalFact(id, o.token().parents())));
                var heads = new ArrayList<TokenHead>();
                var grouped = new LinkedHashMap<Long, List<TokenHead>>();
                for (var object : view.heads()) {
                    long value = valueIds.get(object.token().value());
                    var head = new Head(this, id, revision(object.objectId()), metadata(object.token().metadata()), value);
                    heads.add(head); grouped.computeIfAbsent(value, ignored -> new ArrayList<>()).add(head);
                }
                var alternatives = new ArrayList<TokenAlternative>();
                grouped.forEach((key, basis) -> alternatives.add(new Alternative(this, id, key, descriptor(values.get(key)), basis)));
                var unresolved = view.unresolvedParents().stream()
                        .map(p -> new UnresolvedReference(revision(p.child()), revision(p.parent()))).toList();
                tokens.add(new Token(id, alternatives, heads, unresolved, competition(alternatives)));
            }
            // No secret is used as a hash key after it is wiped.
            for (var secret : redundant) secret.clear();
            ancestry = Map.copyOf(links);
            emit(new State(this, nextState++, new ObservationProgress.Finished(
                    observation.validatedTokens().size() + observation.candidateDiagnostics().size(), !diagnostics.isEmpty()),
                    tokens, diagnostics, ancestry));
            return observation.snapshotDiagnostics().isEmpty()
                    && observation.candidateDiagnostics().stream().noneMatch(d -> d.reason() == TokenStoreObservation.Reason.UNAVAILABLE);
        } finally { local.unlock(); }
    }
    @Override public PasswordChangeResult changePassword(char[] currentPassword, char[] newPassword) {
        return providerAccess(() -> ApplicationVaults.change(bootstrap, root, currentPassword, newPassword));
    }
    @Override public void close() {
        terminate(null);
    }
    private void terminate(Throwable cause) {
        local.lock();
        try {
            if (!closing) { closing = true; terminationCause = cause; }
        } finally { local.unlock(); }
        observer.shutdown();
        gate.lock();
        try {
            if (closed) return;
            local.lock();
            try {
                for (var resource : Set.copyOf(owned)) ApplicationVaults.cleanup(resource);
                owned.clear();
                var secrets = values.values().stream().map(v -> v.credential().secret()).toList();
                valueIds.clear(); values.clear(); secrets.forEach(SecurityBytes::clear);
                Arrays.fill(root, (byte) 0); ancestry = Map.of();
            } finally { local.unlock(); }
            ApplicationVaults.cleanup(publication); ApplicationVaults.cleanup(bootstrap);
            closed = true;
            publisher.terminate(terminationCause);
        } finally { gate.unlock(); }
    }
    void own(AutoCloseable resource) {
        local.lock(); try { owned.add(resource); } finally { local.unlock(); }
    }
    void release(AutoCloseable resource) {
        local.lock(); try { owned.remove(resource); } finally { local.unlock(); }
    }
    TokenValue value(long key) { return Objects.requireNonNull(values.get(key)); }
    Alternative alternative(TokenAlternative reference) {
        Objects.requireNonNull(reference);
        if (!(reference instanceof Alternative a) || a.owner != this) throw new IllegalArgumentException("Foreign alternative");
        return a;
    }
    Head head(TokenHead reference) {
        Objects.requireNonNull(reference);
        if (!(reference instanceof Head h) || h.owner != this) throw new IllegalArgumentException("Foreign head");
        return h;
    }
    private static TokenDescriptor descriptor(TokenValue v) {
        return new TokenDescriptor(TokenStatus.values()[v.status() - 1], v.issuer(), v.account(),
                TotpAlgorithm.values()[v.credential().algorithm() - 1], v.credential().digits(), Duration.ofSeconds(v.credential().period()));
    }
    static org.totipo.TokenId publicId(TokenId id) { return new org.totipo.TokenId(HexFormat.of().formatHex(id.bytes())); }
    static TokenId internalId(org.totipo.TokenId id) { return new TokenId(HexFormat.of().parseHex(id.hex())); }
    static RevisionId revision(ObjectId id) { return new RevisionId(id.filename()); }
    static ObjectId internalId(RevisionId id) { return ObjectId.fromFilename(id.hex()); }
    static ClientMetadata metadata(TokenMetadata m) { return new ClientMetadata(m.clientName(), m.clientTime().map(UInt64::rawBits)); }
    static TokenMetadata metadata(ClientMetadata m) { return new TokenMetadata(m.clientName(), m.clientTimeBits().map(UInt64::new)); }
    static List<ObjectId> parents(Collection<TokenHead> heads) {
        return heads.stream().map(h -> internalId(h.revision())).distinct().sorted(TokenGraph.OBJECT_ORDER).toList();
    }
    TokenCompetition competition(List<TokenAlternative> alternatives) {
        var secrets = new LinkedHashMap<SecurityBytes, List<TokenAlternative>>();
        for (var a : alternatives) secrets.computeIfAbsent(value(alternative(a).key).credential().secret(),
                ignored -> new ArrayList<>()).add(a);
        return new TokenCompetition(field(alternatives, TokenDescriptor::status), field(alternatives, TokenDescriptor::issuer),
                field(alternatives, TokenDescriptor::account), field(alternatives, TokenDescriptor::algorithm),
                field(alternatives, TokenDescriptor::digits), field(alternatives, TokenDescriptor::period),
                new CompetingSecret(secrets.values().stream().map(SecretGroup::new).toList()));
    }
    private static <T> CompetingField<T> field(List<TokenAlternative> alternatives, Function<TokenDescriptor, T> getter) {
        var grouped = new LinkedHashMap<T, List<TokenAlternative>>();
        for (var a : alternatives) grouped.computeIfAbsent(getter.apply(a.descriptor()), ignored -> new ArrayList<>()).add(a);
        return new CompetingField<>(grouped.entrySet().stream().map(e -> new CompetingField.Value<>(e.getKey(), e.getValue())).toList());
    }
    static final class Head implements TokenHead {
        final ApplicationSession owner;
        final org.totipo.TokenId tokenId;
        final RevisionId revision;
        final ClientMetadata metadata;
        final long key;
        Head(ApplicationSession owner, org.totipo.TokenId tokenId, RevisionId revision, ClientMetadata metadata, long key) {
            this.owner = owner; this.tokenId = tokenId; this.revision = revision; this.metadata = metadata; this.key = key;
        }
        @Override public org.totipo.TokenId tokenId() { return tokenId; }
        @Override public RevisionId revision() { return revision; }
        @Override public ClientMetadata metadata() { return metadata; }
        @Override public boolean equals(Object other) {
            return other instanceof Head h && owner == h.owner && tokenId.equals(h.tokenId) && revision.equals(h.revision);
        }
        @Override public int hashCode() { return Objects.hash(System.identityHashCode(owner), tokenId, revision); }
    }
    static final class Alternative implements TokenAlternative {
        final ApplicationSession owner;
        final org.totipo.TokenId token;
        final long key;
        final TokenDescriptor descriptor;
        final List<TokenHead> heads;
        Alternative(ApplicationSession owner, org.totipo.TokenId token, long key, TokenDescriptor descriptor, List<TokenHead> heads) {
            this.owner = owner; this.token = token; this.key = key; this.descriptor = descriptor; this.heads = List.copyOf(heads);
        }
        @Override public TokenDescriptor descriptor() { return descriptor; }
        @Override public List<TokenHead> heads() { return heads; }
        @Override public boolean equals(Object other) {
            return other instanceof Alternative a && owner == a.owner && token.equals(a.token) && key == a.key;
        }
        @Override public int hashCode() { return Objects.hash(System.identityHashCode(owner), token, key); }
    }
    private record Token(org.totipo.TokenId id, List<TokenAlternative> alternatives, List<TokenHead> heads,
                         List<UnresolvedReference> unresolvedReferences, TokenCompetition competingValues) implements TokenState {
        Token { alternatives = List.copyOf(alternatives); heads = List.copyOf(heads); unresolvedReferences = List.copyOf(unresolvedReferences); }
        @Override public boolean hasConflict() { return alternatives.size() > 1; }
    }
    static final class State implements VaultState {
        final ApplicationSession owner;
        final long sequence;
        private final ObservationProgress observation;
        private final List<TokenState> tokens;
        private final List<VaultDiagnostic> diagnostics;
        private final Map<ObjectId, CausalFact> causalFacts;
        State(ApplicationSession owner, long sequence, ObservationProgress observation, List<TokenState> tokens, List<VaultDiagnostic> diagnostics) {
            this(owner, sequence, observation, tokens, diagnostics, Map.of());
        }
        State(ApplicationSession owner, long sequence, ObservationProgress observation, List<TokenState> tokens,
              List<VaultDiagnostic> diagnostics, Map<ObjectId, CausalFact> causalFacts) {
            this.owner = owner; this.sequence = sequence; this.observation = observation;
            this.tokens = List.copyOf(tokens); this.diagnostics = List.copyOf(diagnostics);
            this.causalFacts = Map.copyOf(causalFacts);
        }
        @Override public ObservationProgress observation() { return observation; }
        @Override public List<TokenState> tokens() { return tokens; }
        @Override public List<VaultDiagnostic> diagnostics() { return diagnostics; }
        @Override public Optional<TokenState> token(org.totipo.TokenId id) {
            Objects.requireNonNull(id); return tokens.stream().filter(t -> t.id().equals(id)).findFirst();
        }
        @Override public CreateToken createToken() { return owner.access(() -> owner.new Create()); }
        @Override public UpdateToken update(TokenHead reference) {
            return owner.access(() -> {
                var h = owner.head(reference);
                return owner.new Update(h.tokenId, List.of(internalId(h.revision)), owner.value(h.key));
            });
        }
        @Override public UpdateToken update(TokenAlternative reference) {
            return owner.access(() -> {
                var a = owner.alternative(reference);
                var matching = token(a.token).stream().flatMap(t -> t.alternatives().stream())
                        .filter(v -> owner.alternative(v).key == a.key).flatMap(v -> v.heads().stream()).toList();
                return owner.new Update(a.token, parents(matching.isEmpty() ? a.heads : matching), owner.value(a.key));
            });
        }
        @Override public MergeToken merge(org.totipo.TokenId tokenId) {
            return owner.access(() -> merge(token(Objects.requireNonNull(tokenId))
                    .orElseThrow(() -> new IllegalArgumentException("Token not in state")).alternatives()));
        }
        @Override public MergeToken merge(Collection<TokenAlternative> selected) {
            return owner.access(() -> {
                var alternatives = List.copyOf(selected);
                if (alternatives.isEmpty()) throw new IllegalArgumentException("Empty merge basis");
                var id = owner.alternative(alternatives.get(0)).token;
                for (var a : alternatives) if (!owner.alternative(a).token.equals(id)) throw new IllegalArgumentException("Mixed tokens");
                var basis = parents(alternatives.stream().flatMap(a -> a.heads().stream()).toList());
                var frontier = token(id).map(t -> parents(t.heads())).orElse(List.of());
                return owner.new Merge(id, basis, frontier, alternatives, causalFacts);
            });
        }
        @Override public TotpCode generateTotp(TokenAlternative reference, Instant time) {
            return owner.access(() -> {
                var value = owner.value(owner.alternative(reference).key);
                long seconds = Objects.requireNonNull(time).getEpochSecond();
                String code = Totp.generate(value.credential(), seconds);
                long period = value.credential().period();
                var start = Instant.ofEpochSecond(seconds / period * period);
                return new TotpCode(code, start, start.plusSeconds(period));
            });
        }
    }
    private abstract class Editor<T extends TokenEditor<T>> implements TokenEditor<T> {
        final org.totipo.TokenId token;
        final List<ObjectId> basis;
        TokenStatus status;
        String issuer, account;
        TotpAlgorithm algorithm;
        Integer digits;
        Duration period;
        ClientMetadata metadata = ClientMetadata.empty();
        SecurityBytes override;
        Long inheritedSecret;
        boolean ended;
        Editor(org.totipo.TokenId token, List<ObjectId> basis) { this.token = token; this.basis = List.copyOf(basis); own(this); }
        abstract T self();
        void editable() { requireOpen(); if (ended) throw new IllegalStateException("Builder terminal or closed"); }
        T edit(Runnable action) { return access(() -> { editable(); action.run(); return self(); }); }
        @Override public T status(TokenStatus value) { return edit(() -> status = Objects.requireNonNull(value)); }
        @Override public T issuer(String value) { return edit(() -> { StrictUtf8.encode(Objects.requireNonNull(value), 256); issuer = value; }); }
        @Override public T account(String value) { return edit(() -> { StrictUtf8.encode(Objects.requireNonNull(value), 256); account = value; }); }
        @Override public T algorithm(TotpAlgorithm value) { return edit(() -> algorithm = Objects.requireNonNull(value)); }
        @Override public T digits(int value) { return edit(() -> { if (value < 6 || value > 8) throw new IllegalArgumentException("Digits"); digits = value; }); }
        @Override public T period(Duration value) {
            return edit(() -> {
                Objects.requireNonNull(value);
                if (value.getNano() != 0 || value.getSeconds() < 1 || value.getSeconds() > 0xffff_ffffL)
                    throw new IllegalArgumentException("Period");
                period = value;
            });
        }
        @Override public T secret(NewSecret value) {
            return edit(() -> {
                byte[] bytes = Objects.requireNonNull(value).copy();
                try { if (override != null) override.clear(); override = new SecurityBytes(bytes, bytes.length); inheritedSecret = null; }
                finally { Arrays.fill(bytes, (byte) 0); }
            });
        }
        @Override public T metadata(ClientMetadata value) { return edit(() -> { ApplicationSession.metadata(Objects.requireNonNull(value)); metadata = value; }); }
        void prefill(TokenValue value) {
            var d = descriptor(value);
            status = d.status(); issuer = d.issuer(); account = d.account(); algorithm = d.algorithm(); digits = d.digits(); period = d.period();
            inheritedSecret = valueIds.get(value);
        }
        List<String> unresolved() {
            var fields = new ArrayList<String>();
            if (status == null) fields.add("status"); if (issuer == null) fields.add("issuer");
            if (account == null) fields.add("account"); if (algorithm == null) fields.add("algorithm");
            if (digits == null) fields.add("digits"); if (period == null) fields.add("period");
            if (override == null && inheritedSecret == null) fields.add("secret");
            return List.copyOf(fields);
        }
        Frozen freeze() {
            var secret = override == null ? value(inheritedSecret).credential().secret() : override;
            byte[] copy = secret.bytes();
            var ownedSecret = new SecurityBytes(copy, copy.length); Arrays.fill(copy, (byte) 0);
            try {
                var value = new TokenValue(status.ordinal() + 1, issuer, account,
                        new TokenValue.Credential(algorithm.ordinal() + 1, digits, period.getSeconds(), ownedSecret));
                var plan = token == null ? TokenPublicationPlan.planNew(value, ApplicationSession.metadata(metadata), root)
                        : TokenPublicationPlan.planAssertion(internalId(token), basis, value, ApplicationSession.metadata(metadata), root);
                return new Frozen(plan);
            } finally { ownedSecret.clear(); }
        }
        @Override public SaveResult save() {
            return providerAccess(() -> {
                local.lock();
                Frozen operation;
                try {
                    editable();
                    if (!unresolved().isEmpty()) return new SaveResult.Failed(SaveResult.Reason.UNRESOLVED_FIELDS);
                    try { operation = freeze(); }
                    catch (IllegalStateException preparation) { return new SaveResult.Failed(SaveResult.Reason.PREPARATION_FAILED); }
                } finally { local.unlock(); }
                if (this instanceof Merge merge) {
                    if (!observe()) { operation.close(); return new SaveResult.Failed(SaveResult.Reason.OBSERVATION_UNAVAILABLE); }
                    if (closing) { operation.close(); return new SaveResult.Failed(SaveResult.Reason.SESSION_CLOSING); }
                    if (merge.additional()) {
                        close();
                        return new SaveResult.AdditionalConflict(current, new Partial(operation));
                    }
                }
                if (closing) { operation.close(); return new SaveResult.Failed(SaveResult.Reason.SESSION_CLOSING); }
                close(); // Semantic freeze precedes the first potentially successful provider call.
                return operation.publish();
            });
        }
        @Override public void close() {
            local.lock();
            try { ended = true; if (override != null) override.clear(); override = null; inheritedSecret = null; release(this); }
            finally { local.unlock(); }
        }
    }
    private final class Create extends Editor<CreateToken> implements CreateToken {
        Create() {
            super(null, List.of()); status = TokenStatus.ACTIVE; issuer = ""; account = "";
            algorithm = TotpAlgorithm.SHA1; digits = 6; period = Duration.ofSeconds(30);
        }
        @Override CreateToken self() { return this; }
    }
    private final class Update extends Editor<UpdateToken> implements UpdateToken {
        Update(org.totipo.TokenId token, List<ObjectId> basis, TokenValue value) { super(token, basis); prefill(value); }
        @Override UpdateToken self() { return this; }
    }
    private final class Merge extends Editor<MergeToken> implements MergeToken {
        final List<ObjectId> frontier;
        final TokenCompetition competition;
        final List<MergeSecretChoice> choices;
        final Map<ObjectId, CausalFact> originalAncestry;
        Merge(org.totipo.TokenId token, List<ObjectId> basis, List<ObjectId> frontier, List<TokenAlternative> selected,
              Map<ObjectId, CausalFact> originalAncestry) {
            super(token, basis); this.frontier = List.copyOf(frontier); competition = competition(selected);
            this.originalAncestry = originalAncestry;
            status = agreed(competition.status()); issuer = agreed(competition.issuer()); account = agreed(competition.account());
            algorithm = agreed(competition.algorithm()); digits = agreed(competition.digits()); period = agreed(competition.period());
            choices = competition.secret().groups().stream().map(g -> (MergeSecretChoice) new Choice(this, g.alternatives())).toList();
            if (choices.size() == 1) inheritedSecret = alternative(choices.get(0).alternatives().get(0)).key;
        }
        @Override MergeToken self() { return this; }
        @Override public TokenCompetition competingValues() { return competition; }
        @Override public List<MergeSecretChoice> secretChoices() { return choices; }
        @Override public List<String> unresolvedFields() { return access(() -> { editable(); return unresolved(); }); }
        @Override public MergeToken secret(MergeSecretChoice selection) {
            return edit(() -> {
                Objects.requireNonNull(selection);
                if (!(selection instanceof Choice choice) || choice.merge != this) throw new IllegalArgumentException("Foreign merge choice");
                if (override != null) override.clear(); override = null;
                inheritedSecret = alternative(choice.alternatives.get(0)).key;
            });
        }
        boolean additional() {
            // Walk the newly observed ancestry from F0, including references that resolved this pass.
            var contained = new HashSet<ObjectId>();
            var pending = new ArrayDeque<>(frontier);
            while (!pending.isEmpty()) {
                var id = pending.removeFirst();
                if (contained.add(id)) {
                    var original = originalAncestry.get(id);
                    if (original != null && original.token().equals(token)) pending.addAll(original.parents());
                    var observed = ancestry.get(id);
                    if (observed != null && observed.token().equals(token)) pending.addAll(observed.parents());
                }
            }
            return current.token(token).stream().flatMap(t -> t.heads().stream())
                    .anyMatch(h -> !contained.contains(internalId(h.revision())));
        }
    }
    private static <T> T agreed(CompetingField<T> field) { return field.values().size() == 1 ? field.values().get(0).value() : null; }
    private final class Choice implements MergeSecretChoice {
        final Merge merge;
        final List<TokenAlternative> alternatives;
        Choice(Merge merge, List<TokenAlternative> alternatives) { this.merge = merge; this.alternatives = List.copyOf(alternatives); }
        @Override public List<TokenAlternative> alternatives() { return alternatives; }
    }
    private record Authored(ObjectId id, byte[] envelope) { }
    /** Exact ciphertext stages, not a recipe to regenerate semantics on retry. */
    private final class Frozen implements AutoCloseable {
        final org.totipo.TokenId token;
        List<Authored> stages;
        boolean uncertain, ended;
        Frozen(TokenPublicationPlan plan) {
            token = publicId(plan.stages().get(0).token().tokenId());
            var authored = new ArrayList<Authored>();
            for (var stage : plan.stages()) {
                byte[] plaintext = TokenWriter.write(stage.token());
                try {
                    var envelope = V1EnvelopeWriter.seal(root, plaintext);
                    if (!envelope.id().equals(stage.objectId())) throw new IllegalStateException("Authored identity mismatch");
                    authored.add(new Authored(stage.objectId(), envelope.bytes()));
                } finally { Arrays.fill(plaintext, (byte) 0); }
            }
            stages = List.copyOf(authored); own(this);
        }
        void active() { requireOpen(); if (ended) throw new IllegalStateException("Operation closed or saved"); }
        PartialSaveResult publish() {
            if (ended) throw new IllegalStateException("Operation closed or saved");
            if (closing) {
                if (uncertain) return new SaveResult.PublicationUncertain(new Retry(this));
                return new SaveResult.Failed(SaveResult.Reason.SESSION_CLOSING);
            }
            return attempt();
        }
        RetryResult retry() {
            if (!uncertain || ended) throw new IllegalStateException("Not an active uncertain operation");
            if (closing) return new SaveResult.PublicationUncertain(new Retry(this));
            return attempt();
        }
        private RetryResult attempt() {
            try {
                for (var stage : stages) {
                    uncertain = true; // The SPI cannot prove non-publication after entry, including unchecked failures.
                    if (publication.publish(stage.id(), stage.envelope().clone()) == null)
                        throw new java.io.IOException("No publication acknowledgement");
                }
            } catch (java.io.IOException | RuntimeException failure) {
                return new SaveResult.PublicationUncertain(new Retry(this));
            }
            var result = new SaveResult.Saved(token, stages.stream().map(s -> revision(s.id())).toList());
            close();
            // Publication certainty is independent of a later observation's availability.
            if (!closing) {
                try { requestRefresh(); } catch (SessionClosedException closingNow) { /* Saved remains saved. */ }
            }
            return result;
        }
        @Override public void close() {
            gate.lock();
            try {
                ended = true;
                for (var stage : stages) Arrays.fill(stage.envelope(), (byte) 0);
                stages = List.of();
                release(this);
            }
            finally { gate.unlock(); }
        }
    }
    private final class Retry implements PublicationRetry {
        private final Frozen operation;
        private boolean ended;
        Retry(Frozen operation) { this.operation = operation; }
        @Override public RetryResult retryPublication() {
            return providerAccess(() -> {
                if (ended) throw new IllegalStateException("Retry closed or transferred");
                operation.active();
                var result = operation.retry();
                ended = true; // Uncertain result transfers capability to its independent next handle.
                return result;
            });
        }
        @Override public void close() {
            gate.lock();
            try { if (!ended) { ended = true; operation.close(); } } finally { gate.unlock(); }
        }
    }
    private final class Partial implements PartialResolution {
        private final Frozen operation;
        private boolean ended;
        Partial(Frozen operation) { this.operation = operation; }
        @Override public PartialSaveResult save() {
            return providerAccess(() -> {
                if (ended) throw new IllegalStateException("Partial resolution closed or transferred");
                operation.active();
                var result = operation.publish();
                if (!(result instanceof SaveResult.Failed)) ended = true;
                return result;
            });
        }
        @Override public void close() {
            gate.lock();
            try { if (!ended) { ended = true; operation.close(); } } finally { gate.unlock(); }
        }
    }
}
