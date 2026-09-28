package dev.totipo.format;

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

import static dev.totipo.format.VaultLifecycleResult.Status.*;

/** r15 §§8–10 orchestration. Synchronous, thread-confined, scoped operations.
 * Borrows explicit stores/source/password; caller keeps exclusive local storage
 * ownership throughout and closes stores afterward. All streams/snapshots/staged
 * handles are closed here. No live session escapes; discovery reconstructs each pass.
 * No retained candidate/root recovery or application session. */
final class VaultLifecycle {
    private final VaultBootstrapStorage bootstrap;
    private final VaultBindingStore memory;
    private final DiscoverySource source;
    private final EntropySource entropy;
    private final VaultBootstrapWriter writer;
    private final VaultUnlocker unlocker;

    VaultLifecycle(VaultBootstrapStorage bootstrap, VaultBindingStore memory, DiscoverySource source) {
        this(bootstrap, memory, source, new EntropySource.Jdk(),
                new VaultBootstrapWriter(), new VaultUnlocker());
    }
    VaultLifecycle(VaultBootstrapStorage bootstrap, VaultBindingStore memory, DiscoverySource source,
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
        VaultBindingStore.Binding bindingState;
        try { bindingState = memory.read(); }
        catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
        var invalid = localProblem(bindingState);
        if (invalid != null) { return fail(invalid); }
        if (bindingState.state() != VaultBindingStore.State.ABSENT) {
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
        byte[] root = new byte[32], salt = new byte[16], nonce = new byte[12];
        try {
            byte[] candidate, binding;
            try {
                entropy.fill(root); entropy.fill(salt); entropy.fill(nonce);
                candidate = writer.encode(password, root, salt, nonce);
                try (var intended = VaultUnlockResult.unlocked(root)) { binding = intended.binding(); }
                if (!matches(candidate, password, root, binding)) { return fail(CRYPTO_CONSTRUCTION_FAILED); }
            } catch (RuntimeException e) { return fail(CRYPTO_CONSTRUCTION_FAILED); }
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
                try { memory.create(binding); } catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
            } catch (IOException | RuntimeException e) { return fail(PUBLICATION_INCOMPLETE); }
            finally {
                if (staged != null) {
                    try { staged.close(); }
                    catch (IOException | RuntimeException e) {
                        // Noncanonical residue cannot change establishment or mask an earlier failure.
                    }
                }
            }
            return discovered(true, root);
        } finally {
            Arrays.fill(root, (byte) 0); Arrays.fill(salt, (byte) 0); Arrays.fill(nonce, (byte) 0);
        }
    }

    /** Explicit new-client authorization; authenticate before creating an absent binding. */
    VaultLifecycleResult configureExisting(byte[] password) { return open(password); }

    /** Authenticate canonical VAULT and establish the local binding when absent. */
    VaultLifecycleResult openConfigured(byte[] password) { return open(password); }


    /** Rewrap only the established root. Passwords are synchronously borrowed.
     * Local binding is read-only; no discovery or semantic policy is evaluated.
     * Historical bootstrap/password copies remain usable; this is not revocation. */
    PasswordChangeStatus changePassword(byte[] currentPassword, byte[] newPassword) {
        if (!(bootstrap instanceof VaultBootstrapReplacementStorage replacement)) {
            return PasswordChangeStatus.REPLACEMENT_UNSUPPORTED;
        }
        VaultBindingStore.Binding bindingState;
        try { bindingState = memory.read(); }
        catch (IOException e) { return PasswordChangeStatus.LOCAL_STORAGE_UNAVAILABLE; }
        if (bindingState.state() == VaultBindingStore.State.ABSENT) { return PasswordChangeStatus.LOCAL_BINDING_ABSENT; }
        if (bindingState.state() == VaultBindingStore.State.CORRUPT) { return PasswordChangeStatus.LOCAL_BINDING_CORRUPT; }
        byte[] canonical;
        try { canonical = read(bootstrap.openCanonicalRead()); }
        catch (IOException e) { return PasswordChangeStatus.BOOTSTRAP_STORAGE_UNAVAILABLE; }
        if (canonical == null) { return PasswordChangeStatus.CURRENT_CANONICAL_ABSENT; }
        if (currentPassword == null) { return PasswordChangeStatus.CURRENT_INVALID_PASSWORD_INPUT; }
        try (var current = unlocker.unlock(canonical, currentPassword)) {
            switch (current.status()) {
                case AUTHENTICATION_FAILED: return PasswordChangeStatus.CURRENT_AUTHENTICATION_FAILED;
                case INVALID_FORMAT: return PasswordChangeStatus.CURRENT_INVALID_BOOTSTRAP;
                case INVALID_PASSWORD_INPUT: return PasswordChangeStatus.CURRENT_INVALID_PASSWORD_INPUT;
                case UNLOCKED: break;
            }
            byte[] binding = bindingState.bytes();
            if (!MessageDigest.isEqual(binding, current.binding())) {
                return PasswordChangeStatus.ESTABLISHED_BINDING_MISMATCH;
            }
            if (newPassword == null || !PasswordBytes.valid(newPassword)) {
                return PasswordChangeStatus.INVALID_NEW_PASSWORD_INPUT;
            }
            byte[] root = current.root(), salt = new byte[16], nonce = new byte[12];
            try {
                byte[] candidate;
                try {
                    entropy.fill(salt); entropy.fill(nonce);
                    candidate = writer.encode(newPassword, root, salt, nonce);
                    if (!matches(candidate, newPassword, root, binding)) {
                        return PasswordChangeStatus.CRYPTO_CONSTRUCTION_FAILED;
                    }
                } finally {
                    Arrays.fill(salt, (byte) 0); Arrays.fill(nonce, (byte) 0);
                }
                VaultBootstrapReplacementStorage.StagedReplacement staged = null;
                try {
                    staged = replacement.stageReplacement(candidate);
                    if (!matches(read(staged.openRead()), newPassword, root, binding)) {
                        return PasswordChangeStatus.REWRAP_INCOMPLETE;
                    }
                    staged.replaceCanonicalDurably();
                    byte[] installed = read(bootstrap.openCanonicalRead());
                    if (installed == null || !matches(installed, newPassword, root, binding)) {
                        return PasswordChangeStatus.REWRAP_INCOMPLETE;
                    }
                    return PasswordChangeStatus.SUCCESS;
                } catch (IOException | RuntimeException e) {
                    return PasswordChangeStatus.REWRAP_INCOMPLETE;
                } finally {
                    if (staged != null) {
                        try { staged.close(); }
                        catch (IOException | RuntimeException e) { /* Nonauthoritative residue. */ }
                    }
                }
            } finally { Arrays.fill(root, (byte) 0); }
        } catch (RuntimeException e) { return PasswordChangeStatus.CRYPTO_CONSTRUCTION_FAILED; }
    }

    private VaultLifecycleResult open(byte[] password) {
        byte[] canonical;
        try { canonical = read(bootstrap.openCanonicalRead()); }
        catch (IOException e) { return fail(BOOTSTRAP_STORAGE_UNAVAILABLE); }
        if (canonical == null) { return fail(CANONICAL_VAULT_ABSENT); }
        try (var unlocked = unlocker.unlock(canonical, password)) {
            if (unlocked.status() != VaultUnlockResult.Status.UNLOCKED) {
                return fail(switch (unlocked.status()) {
                    case AUTHENTICATION_FAILED -> AUTHENTICATION_FAILED;
                    case INVALID_FORMAT -> INVALID_BOOTSTRAP;
                    case INVALID_PASSWORD_INPUT -> INVALID_PASSWORD_INPUT;
                    default -> throw new AssertionError();
                });
            }
            try {
                var local = memory.read();
                if (local.state() == VaultBindingStore.State.CORRUPT) { return fail(LOCAL_BINDING_CORRUPT); }
                if (local.state() == VaultBindingStore.State.PRESENT
                        && !MessageDigest.isEqual(local.bytes(), unlocked.binding())) { return fail(ESTABLISHED_BINDING_MISMATCH); }
                if (local.state() == VaultBindingStore.State.ABSENT) { memory.create(unlocked.binding()); }
            } catch (IOException e) { return fail(LOCAL_PERSISTENCE_FAILURE); }
            byte[] root = unlocked.root();
            try { return discovered(false, root); }
            finally { Arrays.fill(root, (byte) 0); }
        }
    }
    private static VaultLifecycleResult.Status localProblem(VaultBindingStore.Binding binding) {
        return binding.state() == VaultBindingStore.State.CORRUPT ? LOCAL_BINDING_CORRUPT : null;
    }
    private VaultLifecycleResult discovered(boolean created, byte[] root) {
        return VaultLifecycleResult.established(created, root, DiscoveryCoordinator.discover(source, root));
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
