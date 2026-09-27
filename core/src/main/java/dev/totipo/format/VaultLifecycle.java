package dev.totipo.format;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

import static dev.totipo.format.VaultLifecycleResult.Status.*;

/** r13 §§8–10 orchestration. Synchronous, thread-confined, scoped operations.
 * Borrows explicit stores/source/password; caller keeps exclusive local storage
 * ownership throughout and closes stores afterward. All streams/snapshots/staged
 * handles are closed here. No live session escapes; reopen/replay for another pass.
 * No retained candidate/root recovery, replacement, or application session. */
final class VaultLifecycle {
    private final VaultBootstrapStorage bootstrap;
    private final SecurityMemoryStorage memory;
    private final DiscoverySource source;
    private final EntropySource entropy;
    private final VaultBootstrapWriter writer;
    private final VaultUnlocker unlocker;

    VaultLifecycle(VaultBootstrapStorage bootstrap, SecurityMemoryStorage memory, DiscoverySource source) {
        this(bootstrap, memory, source, new EntropySource.Jdk(),
                new VaultBootstrapWriter(), new VaultUnlocker());
    }
    VaultLifecycle(VaultBootstrapStorage bootstrap, SecurityMemoryStorage memory, DiscoverySource source,
                   EntropySource entropy, VaultBootstrapWriter writer, VaultUnlocker unlocker) {
        this.bootstrap = Objects.requireNonNull(bootstrap);
        this.memory = Objects.requireNonNull(memory);
        this.source = Objects.requireNonNull(source);
        this.entropy = Objects.requireNonNull(entropy);
        this.writer = Objects.requireNonNull(writer);
        this.unlocker = Objects.requireNonNull(unlocker);
    }

    /** Explicitly new local configuration and new synchronized vault. */
    VaultLifecycleResult createNew(byte[] password) {
        SecurityMemorySession session;
        try { session = SecurityMemorySession.open(memory); }
        catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
        var invalid = localProblem(session);
        if (invalid != null) { return fail(invalid); }
        if (session.establishment().phase() != LocalEstablishment.Phase.UNESTABLISHED) {
            return fail(LOCAL_STATE_NOT_FRESH);
        }
        try (var canonical = bootstrap.openCanonicalRead()) {
            if (canonical != null) { return fail(CANONICAL_VAULT_PRESENT); }
        } catch (IOException e) { return fail(BOOTSTRAP_STORAGE_UNAVAILABLE); }
        // A fixed name snapshot proves only present emptiness, not future synchronization absence.
        VaultLifecycleResult.Status preflight = null;
        try (var snapshot = source.snapshot()) {
            if (!snapshot.complete()) { preflight = CREATE_BLOCKED_DISCOVERY_INCOMPLETE; }
            else if (!snapshot.candidates().isEmpty()) { preflight = CREATE_BLOCKED_EXISTING_OBJECT_CANDIDATES; }
        } catch (IOException | SecurityException | UnsupportedOperationException e) {
            return fail(CREATE_BLOCKED_DISCOVERY_INCOMPLETE);
        }
        if (preflight != null) { return fail(preflight); }
        if (!PasswordBytes.valid(password)) { return fail(INVALID_PASSWORD_INPUT); }
        try {
            if (session.head().status() == SecurityMemoryJournal.Status.ABSENT) {
                session = SecurityMemorySession.initializeNew(memory);
            }
        } catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
        byte[] root = new byte[32], salt = new byte[16], nonce = new byte[12];
        try {
            byte[] candidate, binding;
            try {
                entropy.fill(root); entropy.fill(salt); entropy.fill(nonce);
                candidate = writer.encode(password, root, salt, nonce);
                try (var intended = VaultUnlockResult.unlocked(root)) { binding = intended.binding(); }
                if (!matches(candidate, password, root, binding)) { return fail(CRYPTO_CONSTRUCTION_FAILED); }
            } catch (RuntimeException e) { return fail(CRYPTO_CONSTRUCTION_FAILED); }
            if (!session.persistPending(binding)) { return fail(LOCAL_PERSISTENCE_FAILURE); }
            VaultBootstrapStorage.StagedBootstrap staged = null;
            try {
                staged = bootstrap.stageInitial(candidate);
                byte[] stagedBytes = read(staged.openRead());
                if (!matches(stagedBytes, password, root, binding)) { return fail(PUBLICATION_INCOMPLETE); }
                staged.installInitialDurably();
                byte[] installed = read(bootstrap.openCanonicalRead());
                if (installed == null || !matches(installed, password, root, binding)) {
                    return fail(PUBLICATION_INCOMPLETE);
                }
                if (!session.establishFromPending(binding)) { return fail(LOCAL_PERSISTENCE_FAILURE); }
            } catch (IOException | RuntimeException e) { return fail(PUBLICATION_INCOMPLETE); }
            finally {
                if (staged != null) {
                    try { staged.close(); }
                    catch (IOException | RuntimeException e) {
                        // Noncanonical residue cannot change establishment or mask an earlier failure.
                    }
                }
            }
            return discovered(true, root, session);
        } finally {
            Arrays.fill(root, (byte) 0); Arrays.fill(salt, (byte) 0); Arrays.fill(nonce, (byte) 0);
        }
    }

    /** Explicit new-client authorization; authenticate before initializing absent memory. */
    VaultLifecycleResult configureExisting(byte[] password) { return open(password, Intent.CONFIGURE_EXISTING); }

    /** Existing local configuration: absence of memory is never a fresh-client signal. */
    VaultLifecycleResult openConfigured(byte[] password) { return open(password, Intent.OPEN_CONFIGURED); }

    private enum Intent { CONFIGURE_EXISTING, OPEN_CONFIGURED }

    private VaultLifecycleResult open(byte[] password, Intent intent) {
        SecurityMemorySession session;
        try { session = SecurityMemorySession.open(memory); }
        catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
        var invalid = localProblem(session);
        if (invalid != null) { return fail(invalid); }
        boolean absent = session.head().status() == SecurityMemoryJournal.Status.ABSENT;
        var phase = session.establishment().phase();
        if (intent == Intent.OPEN_CONFIGURED && absent) { return fail(LOCAL_SECURITY_MEMORY_MISSING); }
        if (intent == Intent.CONFIGURE_EXISTING && phase != LocalEstablishment.Phase.UNESTABLISHED
                || intent == Intent.OPEN_CONFIGURED && phase == LocalEstablishment.Phase.UNESTABLISHED) {
            return fail(LOCAL_STATE_NOT_FRESH);
        }
        byte[] canonical;
        try { canonical = read(bootstrap.openCanonicalRead()); }
        catch (IOException e) { return fail(BOOTSTRAP_STORAGE_UNAVAILABLE); }
        if (canonical == null) {
            return fail(phase == LocalEstablishment.Phase.PENDING ? PENDING_CANONICAL_ABSENT : CANONICAL_VAULT_ABSENT);
        }
        try (var unlocked = unlocker.unlock(canonical, password)) {
            if (unlocked.status() != VaultUnlockResult.Status.UNLOCKED) {
                return fail(switch (unlocked.status()) {
                    case AUTHENTICATION_FAILED -> AUTHENTICATION_FAILED;
                    case INVALID_FORMAT -> INVALID_BOOTSTRAP;
                    case INVALID_PASSWORD_INPUT -> INVALID_PASSWORD_INPUT;
                    default -> throw new AssertionError();
                });
            }
            byte[] binding = unlocked.binding();
            if (phase != LocalEstablishment.Phase.UNESTABLISHED
                    && !MessageDigest.isEqual(binding, session.establishment().binding().bytes())) {
                return fail(phase == LocalEstablishment.Phase.PENDING
                        ? PENDING_BINDING_MISMATCH : ESTABLISHED_BINDING_MISMATCH);
            }
            if (intent == Intent.CONFIGURE_EXISTING) {
                try { if (absent) { session = SecurityMemorySession.initializeNew(memory); } }
                catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
                if (!session.establishFirstOpen(binding)) { return fail(LOCAL_PERSISTENCE_FAILURE); }
            } else if (phase == LocalEstablishment.Phase.PENDING && !session.establishFromPending(binding)) {
                return fail(LOCAL_PERSISTENCE_FAILURE);
            }
            byte[] root = unlocked.root();
            try { return discovered(false, root, session); }
            finally { Arrays.fill(root, (byte) 0); }
        }
    }

    private static VaultLifecycleResult.Status localProblem(SecurityMemorySession session) {
        return switch (session.head().status()) {
            case CLEAN, ABSENT -> null;
            case INCOMPLETE_TAIL -> LOCAL_TAIL_REPAIR_REQUIRED;
            case CORRUPT, UNSUPPORTED_LOCAL_FORMAT -> LOCAL_SECURITY_MEMORY_INVALID;
        };
    }
    private VaultLifecycleResult discovered(boolean created, byte[] root, SecurityMemorySession session) {
        return VaultLifecycleResult.established(created, root, DiscoveryCoordinator.discover(source, root, session));
    }
    private boolean matches(byte[] bytes, byte[] password, byte[] intended, byte[] binding) {
        try (var unlocked = unlocker.unlock(bytes, password)) {
            if (unlocked.status() != VaultUnlockResult.Status.UNLOCKED) { return false; }
            byte[] recovered = unlocked.root();
            try {
                boolean sameRoot = MessageDigest.isEqual(intended, recovered);
                boolean sameBinding = MessageDigest.isEqual(binding, unlocked.binding());
                return sameRoot & sameBinding;
            } finally { Arrays.fill(recovered, (byte) 0); }
        }
    }
    /** Owns stream. Never consumes more than 88 bytes or allocates from metadata. */
    static byte[] read(InputStream input) throws IOException {
        if (input == null) { return null; }
        try (input) { return input.readNBytes(VaultBootstrap.RECORD_BYTES + 1); }
    }
    private static VaultLifecycleResult fail(VaultLifecycleResult.Status status) {
        return VaultLifecycleResult.failure(status);
    }
}
