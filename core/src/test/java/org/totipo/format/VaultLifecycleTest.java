package org.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static org.totipo.format.VaultLifecycle.PasswordChangeResult.*;
import static org.totipo.format.VaultUnlockResult.Status.*;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class VaultLifecycleTest {
    // Fast deterministic KDF only for fault/ownership matrices. Corpus and NIO workflows use Argon2id.
    static final Argon2idKdf FAST = (password, salt) -> CryptoSupport.sha256(password, salt);
    static final byte[] A = CryptoSupport.ascii("A"), B = CryptoSupport.ascii("B");
    static byte[] filled(int length, int value) { byte[] bytes = new byte[length]; Arrays.fill(bytes, (byte) value); return bytes; }
    static byte[] wrapper(byte[] root, byte[] password, int salt) {
        return new VaultBootstrapWriter(FAST).encode(password, root, filled(16, salt), filled(12, salt));
    }
    static VaultLifecycle lifecycle(EntropySource entropy) {
        return new VaultLifecycle(new VaultBootstrapWriter(FAST), new VaultUnlocker(FAST), entropy);
    }
    static final class Draws implements EntropySource {
        final List<byte[]> buffers = new ArrayList<>();
        final List<Integer> sizes = new ArrayList<>();
        @Override public void fill(byte[] bytes) {
            assertFalse(buffers.stream().anyMatch(previous -> previous == bytes));
            sizes.add(bytes.length); buffers.add(bytes); Arrays.fill(bytes, (byte) (buffers.size() + 30));
        }
        void wiped() { for (var bytes : buffers) assertArrayEquals(new byte[bytes.length], bytes); }
    }

    @Test void creationDrawsIndependentFieldsAndReturnsOwnedRoot() throws Exception {
        var store = new VaultTestStore(); var draws = new Draws(); byte[] password = A.clone();
        var result = lifecycle(draws).createNew(store, password);
        assertEquals(VaultLifecycle.CreationStatus.CREATED, result.status());
        assertEquals(List.of(32, 16, 12), draws.sizes); draws.wiped();
        assertEquals(List.of("read", "stage", "stage-read", "install"), store.events);
        assertArrayEquals(A, password);
        assertArrayEquals(filled(32, 31), result.root());
        byte[] copy = result.root(); copy[0] ^= 1; assertArrayEquals(filled(32, 31), result.root());
        assertArrayEquals(CryptoSupport.vaultFingerprint(filled(32, 31)), result.fingerprint());
        assertEquals("CreationResult[CREATED]", result.toString());
        for (var bytes : store.callerArrays) assertArrayEquals(new byte[bytes.length], bytes);
        result.close(); result.close(); assertThrows(IllegalStateException.class, result::root);
        assertThrows(IllegalStateException.class, result::fingerprint);
        try (var opened = lifecycle(draws).open(store, A)) { assertArrayEquals(filled(32, 31), opened.root()); }
    }

    @Test void openOwnsPrivateRootAndCloseWipesItWithoutDiagnostics() throws Exception {
        var store = new VaultTestStore(); store.canonical = wrapper(filled(32, 77), A, 1);
        var opened = lifecycle(bytes -> fail()).open(store, A);
        assertEquals(UNLOCKED, opened.status()); assertEquals("VaultUnlockResult[UNLOCKED]", opened.toString());
        byte[] copy = opened.root(); copy[0] = 0; assertArrayEquals(filled(32, 77), opened.root());
        var field = VaultUnlockResult.class.getDeclaredField("root"); field.setAccessible(true);
        byte[] owned = (byte[]) field.get(opened);
        opened.close(); opened.close(); assertArrayEquals(new byte[32], owned);
        assertThrows(IllegalStateException.class, opened::root); assertThrows(IllegalStateException.class, opened::fingerprint);
    }

    @Test void openSeparatesAbsenceUnavailableMalformedPasswordAndAuthentication() {
        var store = new VaultTestStore(); var lifecycle = lifecycle(bytes -> fail());
        try (var opened = lifecycle.open(store, A)) { assertEquals(ABSENT, opened.status()); }
        store.unreadable = true;
        try (var opened = lifecycle.open(store, A)) { assertEquals(UNAVAILABLE, opened.status()); }
        store.unreadable = false; store.canonical = new byte[87];
        try (var opened = lifecycle.open(store, A)) { assertEquals(INVALID_FORMAT, opened.status()); }
        store.canonical = wrapper(new byte[32], A, 1);
        try (var opened = lifecycle.open(store, B)) { assertEquals(AUTHENTICATION_FAILED, opened.status()); }
        try (var opened = lifecycle.open(store, new byte[]{(byte) 0xff})) { assertEquals(INVALID_PASSWORD_INPUT, opened.status()); }
    }

    @ParameterizedTest @ValueSource(ints = {0, 86, 88, 1000000})
    void readIsBoundedAndMalformedLengthNeverReachesKdf(int length) {
        int[] read = {0};
        var store = new VaultBootstrapStorage() {
            @Override public InputStream openCanonicalRead() {
                return new InputStream() {
                    @Override public int read() { return read[0] == length ? -1 : (++read[0] > 0 ? 0 : -1); }
                };
            }
            @Override public StagedBootstrap stageInitial(byte[] bytes) { throw new AssertionError(); }
            @Override public void close() {}
        };
        var lifecycle = new VaultLifecycle(new VaultBootstrapWriter(FAST),
                new VaultUnlocker((password, salt) -> { fail("Malformed input reached KDF"); return null; }), bytes -> fail());
        try (var opened = lifecycle.open(store, A)) { assertEquals(INVALID_FORMAT, opened.status()); }
        assertEquals(Math.min(length, 88), read[0]);
    }

    @Test void badMagicVersionAndPasswordNeverReachKdf() {
        byte[] valid = wrapper(new byte[32], A, 1);
        var lifecycle = new VaultLifecycle(new VaultBootstrapWriter(FAST),
                new VaultUnlocker((p, s) -> { fail("Invalid input reached KDF"); return null; }), bytes -> fail());
        for (int offset : List.of(0, 10)) {
            var store = new VaultTestStore(); store.canonical = valid.clone(); store.canonical[offset] ^= 1;
            try (var opened = lifecycle.open(store, A)) { assertEquals(INVALID_FORMAT, opened.status()); }
        }
        for (byte[] password : List.of(new byte[]{(byte) 0xff}, filled(1025, 65))) {
            var store = new VaultTestStore(); store.canonical = valid.clone();
            try (var opened = lifecycle.open(store, password)) { assertEquals(INVALID_PASSWORD_INPUT, opened.status()); }
        }
    }

    @Test void preflightAndAuthenticationFailuresDoNotDrawEntropyOrStage() {
        var lifecycle = lifecycle(bytes -> fail("Unexpected entropy"));
        var store = new VaultTestStore(); store.canonical = wrapper(new byte[32], A, 1);
        try (var result = lifecycle.createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        assertEquals(FAILED, lifecycle.changePassword(store, B, A));
        assertEquals(FAILED, lifecycle.changePassword(store, A, filled(1025, 65)));
        store.canonical = null;
        assertEquals(FAILED, lifecycle.changePassword(store, A, B));
        try (var result = lifecycle.createNew(store, new byte[]{(byte) 0xff})) {
            assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status());
        }
        assertEquals(0, store.stages);
    }

    @Test void memoryValidationMustSucceedBeforeStaging() {
        var draws = new Draws(); var store = new VaultTestStore();
        var inconsistent = new VaultLifecycle(new VaultBootstrapWriter(FAST),
                new VaultUnlocker((p, s) -> filled(32, 99)), draws);
        try (var result = inconsistent.createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        assertEquals(0, store.stages); draws.wiped();
        // First derive authenticates BASE, subsequent derive rejects writer output.
        int[] calls = {0};
        store.canonical = wrapper(new byte[32], A, 1);
        inconsistent = new VaultLifecycle(new VaultBootstrapWriter(FAST),
                new VaultUnlocker((p, s) -> ++calls[0] == 1 ? FAST.derive(p, s) : filled(32, 99)), draws);
        assertEquals(FAILED, inconsistent.changePassword(store, A, B)); assertEquals(0, store.stages); draws.wiped();
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void tamperedStageIsNeverPublished(boolean replacing) {
        var store = new VaultTestStore(); store.corruptStage = true;
        if (replacing) store.canonical = wrapper(new byte[32], A, 1);
        byte[] before = store.canonical == null ? null : store.canonical.clone();
        var draws = new Draws(); var lifecycle = lifecycle(draws);
        if (replacing) assertEquals(FAILED, lifecycle.changePassword(store, A, B));
        else try (var result = lifecycle.createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        assertArrayEquals(before, store.canonical); assertEquals(0, store.installs + store.replacements);
        assertEquals(1, store.closes); draws.wiped();
    }

    @ParameterizedTest @ValueSource(booleans = {false, true})
    void ambiguousAcknowledgementNeverSucceedsAndLaterOpenSeesActualBytes(boolean residue) {
        for (boolean replacing : List.of(false, true)) {
            var store = new VaultTestStore(); store.durable = false; store.installOnFailure = residue;
            byte[] root = filled(32, 31);
            if (replacing) store.canonical = wrapper(root, A, 1);
            var draws = new Draws(); var lifecycle = lifecycle(draws);
            if (replacing) assertEquals(FAILED, lifecycle.changePassword(store, A, B));
            else try (var result = lifecycle.createNew(store, B)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
            assertEquals(1, store.installs + store.replacements); draws.wiped();
            try (var opened = lifecycle.open(store, residue ? B : A)) {
                assertEquals(residue || replacing ? UNLOCKED : ABSENT, opened.status());
                if (opened.status() == UNLOCKED) assertArrayEquals(root, opened.root());
            }
        }
    }

    @Test void sameAndEmptyPasswordsAreValidRewrapsAndEntropyNeverIncludesRoot() {
        var store = new VaultTestStore(); store.canonical = wrapper(filled(32, 42), A, 1);
        byte[] previous = A;
        for (byte[] next : List.of(A, new byte[0], B)) {
            byte[] base = store.canonical.clone(); var draws = new Draws();
            var lifecycle = lifecycle(draws);
            assertEquals(SUCCESS, lifecycle.changePassword(store, previous, next));
            assertEquals(List.of(16, 12), draws.sizes); draws.wiped();
            assertFalse(Arrays.equals(base, store.canonical));
            try (var opened = lifecycle.open(store, next)) {
                assertArrayEquals(filled(32, 42), opened.root());
                assertArrayEquals(CryptoSupport.vaultFingerprint(filled(32, 42)), opened.fingerprint());
            }
            previous = next;
        }
    }

    @ParameterizedTest @ValueSource(strings = {"same-root", "different-root", "short", "long", "absent", "unavailable"})
    void immediateReobservationControlsReplacement(String change) {
        var store = new VaultTestStore(); byte[] root = filled(32, 42);
        store.canonical = wrapper(root, A, 1);
        byte[] current = switch (change) {
            case "same-root" -> wrapper(root, B, 2);
            case "different-root" -> wrapper(filled(32, 43), B, 2);
            case "short" -> new byte[3];
            case "long" -> new byte[100];
            case "absent", "unavailable" -> null;
            default -> throw new AssertionError();
        };
        store.beforeRead = () -> {
            if (store.reads == 2) { store.canonical = current; store.unreadable = change.equals("unavailable"); }
        };
        var outcome = lifecycle(new Draws()).changePassword(store, A, B);
        assertEquals(current == null ? FAILED : STALE, outcome);
        assertEquals(0, store.replacements); assertArrayEquals(current, store.canonical);
        assertEquals(List.of("read", "stage", "stage-read", "read"), store.events);
    }

    @Test void stageFailureAndCleanupFailureDoNotInventSuccessOrUndoDurableSuccess() {
        var store = new VaultTestStore(); store.beforeStage = () -> { throw new IOException("Injected stage failure"); };
        var draws = new Draws();
        try (var result = lifecycle(draws).createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        draws.wiped(); assertNull(store.canonical); assertEquals(0, store.installs);
        store.beforeStage = () -> {}; store.closeFailure = true;
        try (var result = lifecycle(new Draws()).createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.CREATED, result.status()); }
        assertEquals(SUCCESS, lifecycle(new Draws()).changePassword(store, A, B));
    }

    @ParameterizedTest @ValueSource(strings = {"short", "long", "same-root-wrapper", "different-root"})
    void independentlyValidOrWrongLengthStageCannotReplaceIntendedBytes(String mutation) {
        for (boolean replacing : List.of(false, true)) {
            var store = new VaultTestStore(); byte[] root = filled(32, 31);
            if (replacing) store.canonical = wrapper(root, A, 1);
            store.stagedTransform = bytes -> switch (mutation) {
                case "short" -> Arrays.copyOf(bytes, 86);
                case "long" -> Arrays.copyOf(bytes, 88);
                case "same-root-wrapper" -> wrapper(root, B, 90);
                case "different-root" -> wrapper(filled(32, 99), B, 90);
                default -> throw new AssertionError();
            };
            var lifecycle = lifecycle(new Draws());
            if (replacing) assertEquals(FAILED, lifecycle.changePassword(store, A, B));
            else try (var result = lifecycle.createNew(store, B)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
            assertEquals(0, store.installs + store.replacements);
        }
    }

    @Test void exactBytesAppearingAtInstallationStillDoNotCountAsSuccessfulCreation() {
        var store = new VaultTestStore(); store.beforeInstall = () -> store.canonical = store.staged.clone();
        var lifecycle = lifecycle(new Draws());
        try (var result = lifecycle.createNew(store, A)) { assertEquals(VaultLifecycle.CreationStatus.FAILED, result.status()); }
        assertEquals(1, store.installs);
        try (var opened = lifecycle.open(store, A)) { assertEquals(UNLOCKED, opened.status()); }
    }

    @Test void entropyFailureWipesTemporaryBuffersAndNeverStages() {
        var store = new VaultTestStore(); var buffers = new ArrayList<byte[]>();
        var lifecycle = lifecycle(bytes -> {
            Arrays.fill(bytes, (byte) 99); buffers.add(bytes); throw new IllegalStateException("Entropy unavailable");
        });
        assertThrows(IllegalStateException.class, () -> lifecycle.createNew(store, A));
        for (var buffer : buffers) assertArrayEquals(new byte[buffer.length], buffer);
        store.canonical = wrapper(new byte[32], A, 1);
        assertThrows(IllegalStateException.class, () -> lifecycle.changePassword(store, A, B));
        for (var buffer : buffers) assertArrayEquals(new byte[buffer.length], buffer);
        assertEquals(0, store.stages);
    }

    @Test void emptyPasswordCreationAndMaxLengthUtf8AreProtocolInputs() {
        for (byte[] password : List.of(new byte[0], filled(1024, 65), CryptoSupport.ascii(" padded "))) {
            var store = new VaultTestStore(); var lifecycle = lifecycle(new Draws());
            try (var result = lifecycle.createNew(store, password)) { assertEquals(VaultLifecycle.CreationStatus.CREATED, result.status()); }
            try (var opened = lifecycle.open(store, password)) { assertEquals(UNLOCKED, opened.status()); }
        }
    }
}
