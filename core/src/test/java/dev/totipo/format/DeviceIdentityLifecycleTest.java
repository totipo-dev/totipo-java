package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.DeviceIdentityResult.Status.*;

import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class DeviceIdentityLifecycleTest {
    @Test void exactSelfTestDomainAndNoStorageCapabilities() throws Exception {
        byte[] binding = new byte[32]; binding[0] = 7;
        var store = new FakeDeviceKeyStore();
        try (var result = DeviceIdentityLifecycle.createNew(replay(established(binding)), store)) {
            assertArrayEquals(CryptoSupport.sha256(CryptoSupport.join(
                    CryptoSupport.ascii("totipo-java/device-key-self-test/v1"), new byte[]{0},
                    binding, result.publicKeyX963())), store.lastMessageDigest);
        }
        assertFalse(store.closed); // caller keeps store ownership
        // Structural capability proof: no source, bootstrap, memory-storage, root or UI input.
        assertEquals(0, DeviceIdentityLifecycle.class.getDeclaredFields().length);
        for (String operation : List.of("loadExisting", "createNew")) {
            assertNotNull(DeviceIdentityLifecycle.class.getDeclaredMethod(operation,
                    SecurityMemoryJournal.Replay.class, DeviceProvenanceKeyStore.class));
        }
    }
    @Test void returnedCreateBindingAndPublicKeyMustBeValidated() throws Exception {
        for (int width : new int[]{31, 32, 33}) {
            var store = new FakeDeviceKeyStore();
            store.createdBindingOverride = new byte[width]; store.createdBindingOverride[0] = 1;
            try (var result = DeviceIdentityLifecycle.createNew(replay(established(new byte[32])), store)) {
                assertEquals(width == 32 ? KEY_BINDING_MISMATCH : KEY_MATERIAL_INVALID, result.status());
            }
            assertEquals(0, store.signs); assertEquals(1, store.closes);
        }
        for (boolean nullKey : List.of(false, true)) {
            var store = new FakeDeviceKeyStore(); store.publicOverride = new byte[65]; store.nullPublicKey = nullKey;
            try (var result = DeviceIdentityLifecycle.createNew(replay(established(new byte[32])), store)) {
                assertEquals(KEY_MATERIAL_INVALID, result.status());
            }
            assertEquals(0, store.signs); assertEquals(1, store.closes);
        }
        var store = new FakeDeviceKeyStore(); store.nullCreateResult = true;
        try (var result = DeviceIdentityLifecycle.createNew(replay(established(new byte[32])), store)) {
            assertEquals(KEY_CREATION_INCOMPLETE, result.status());
        }
        assertEquals(1, store.creates); assertEquals(0, store.signs);
    }
    @Test void closeFailuresCannotExposeRejectedSigner() throws Exception {
        var store = new FakeDeviceKeyStore(); store.seed(new byte[32]); store.throwClose = true;
        store.signFault = FakeDeviceKeyStore.SignFault.THROW;
        try (var result = DeviceIdentityLifecycle.loadExisting(replay(established(new byte[32])), store)) {
            assertEquals(KEY_MATERIAL_INVALID, result.status());
            assertThrows(IllegalStateException.class, result::deviceId);
        }
        assertEquals(1, store.closes);
    }
    static byte[] binding(byte[] root) {
        return CryptoSupport.hmac(root, CryptoSupport.ascii("totipo/v1/local-vault-binding"));
    }
    static MemoryJournalStorage established(byte[] binding) throws Exception {
        var memory = new MemoryJournalStorage();
        var session = SecurityMemorySession.initializeNew(memory);
        assertTrue(session.establishFirstOpen(binding));
        return memory;
    }
    static SecurityMemoryJournal.Replay replay(MemoryJournalStorage memory) throws Exception {
        return SecurityMemorySession.open(memory).head();
    }
    @Test void explicitCreateLoadReopenAndJournalInvariance() throws Exception {
        byte[] binding = binding(new byte[32]);
        var memory = established(binding); byte[] before = memory.bytes.clone();
        var store = new FakeDeviceKeyStore();
        try (var absent = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) {
            assertEquals(ABSENT, absent.status());
            assertThrows(IllegalStateException.class, absent::publicKeyX963);
        }
        byte[] id, key;
        try (var result = DeviceIdentityLifecycle.createNew(replay(memory), store)) {
            assertEquals(CREATED_BOUND, result.status());
            id = result.deviceId(); key = result.publicKeyX963();
            assertArrayEquals(P256.deviceId(key), id);
            Arrays.fill(result.deviceId(), (byte) 0);
            Arrays.fill(result.publicKeyX963(), (byte) 0);
            Arrays.fill(result.vaultBinding(), (byte) 0);
            assertArrayEquals(key, result.publicKeyX963());
            assertArrayEquals(binding, result.vaultBinding());
            assertArrayEquals(id, result.deviceId());
            assertFalse(result.toString().contains(java.util.HexFormat.of().formatHex(key)));
            for (int i = 0; i < 32; i++) {
                byte[] message = CryptoSupport.ascii("fixed interoperability message");
                byte[] signature = result.signSha256Ecdsa(message);
                assertTrue(EcdsaDerSignature.isCanonical(signature));
                assertTrue(P256.verify(key, message, signature));
            }
        }
        store.close(); store.reopen();
        try (var loaded = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) {
            assertEquals(AVAILABLE_BOUND, loaded.status()); assertArrayEquals(id, loaded.deviceId());
        }
        assertEquals(1, store.creates); assertEquals(2, store.closes);
        assertArrayEquals(before, memory.bytes);
    }
    @Test void differentRootStopsBeforeSigningAndSameBindingSurvivesRewrap() throws Exception {
        byte[] root = new byte[32], other = new byte[32]; other[0] = 1;
        var a = established(binding(root)); var b = established(binding(other));
        var store = new FakeDeviceKeyStore(); store.seed(binding(root));
        try (var result = DeviceIdentityLifecycle.loadExisting(replay(b), store)) {
            assertEquals(KEY_BINDING_MISMATCH, result.status());
            assertThrows(IllegalStateException.class, () -> result.signSha256Ecdsa(new byte[0]));
        }
        assertEquals(0, store.signs); assertEquals(0, store.creates); assertEquals(1, store.closes);
        // Different password representations of the same root have the same binding.
        var writer = new VaultBootstrapWriter();
        byte[] first = writer.encode(new byte[]{1}, root, new byte[16], new byte[12]);
        byte[] second = writer.encode(new byte[]{2}, root, new byte[16], new byte[12]);
        assertFalse(Arrays.equals(first, second));
        try (var old = new VaultUnlocker().unlock(first, new byte[]{1});
             var changed = new VaultUnlocker().unlock(second, new byte[]{2})) {
            assertArrayEquals(old.binding(), changed.binding());
            for (byte[] same : List.of(old.binding(), changed.binding())) {
                try (var loaded = DeviceIdentityLifecycle.loadExisting(replay(established(same)), store)) {
                    assertEquals(AVAILABLE_BOUND, loaded.status());
                }
            }
        }
        assertArrayEquals(binding(root), replay(a).establishment().binding().bytes());
    }
    @Test void unknownContinuityDoesNotGateIdentityOrChangeJournal() throws Exception {
        var memory = established(new byte[32]);
        var session = SecurityMemorySession.open(memory); assertTrue(session.markUnknown());
        byte[] before = memory.bytes.clone();
        var store = new FakeDeviceKeyStore();
        try (var result = DeviceIdentityLifecycle.createNew(replay(memory), store)) {
            assertEquals(CREATED_BOUND, result.status());
        }
        try (var result = DeviceIdentityLifecycle.loadExisting(replay(memory), store)) {
            assertEquals(AVAILABLE_BOUND, result.status());
        }
        assertEquals(LocalContinuityStatus.LOCAL_CONTINUITY_UNKNOWN, replay(memory).knowledge().continuity());
        assertArrayEquals(before, memory.bytes);
    }
    @Test void establishmentAndReplayGatesNeverReachCustody() throws Exception {
        var absent = new MemoryJournalStorage();
        var fresh = new MemoryJournalStorage(); SecurityMemorySession.initializeNew(fresh);
        var pending = new MemoryJournalStorage(); SecurityMemorySession.initializeNew(pending).persistPending(new byte[32]);
        var corrupt = established(new byte[32]); corrupt.bytes[corrupt.bytes.length - 1] ^= 1;
        var unsupported = new MemoryJournalStorage(); unsupported.bytes = SecurityMemoryJournal.header(); unsupported.bytes[11] = 2;
        var tail = established(new byte[32]); tail.bytes = Arrays.copyOf(tail.bytes, tail.bytes.length + 1);
        var memories = List.of(absent, fresh, pending, corrupt, unsupported, tail);
        var statuses = List.of(LOCAL_SECURITY_MEMORY_MISSING, LOCAL_STATE_NOT_ESTABLISHED,
                LOCAL_STATE_NOT_ESTABLISHED, LOCAL_SECURITY_MEMORY_INVALID,
                LOCAL_SECURITY_MEMORY_INVALID, LOCAL_TAIL_REPAIR_REQUIRED);
        for (int i = 0; i < memories.size(); i++) {
            var store = new FakeDeviceKeyStore(); store.seed(new byte[32]);
            byte[] before = memories.get(i).bytes == null ? null : memories.get(i).bytes.clone();
            try (var load = DeviceIdentityLifecycle.loadExisting(replay(memories.get(i)), store);
                 var create = DeviceIdentityLifecycle.createNew(replay(memories.get(i)), store)) {
                assertEquals(statuses.get(i), load.status()); assertEquals(statuses.get(i), create.status());
            }
            assertEquals(0, store.opens); assertEquals(0, store.creates); assertEquals(0, store.signs);
            assertArrayEquals(before, memories.get(i).bytes);
        }
    }
    @ParameterizedTest @EnumSource(value = FakeDeviceKeyStore.SignFault.class, names = "NONE", mode = EnumSource.Mode.EXCLUDE)
    void signerAnomaliesFailClosedOnLoadAndCreate(FakeDeviceKeyStore.SignFault fault) throws Exception {
        for (boolean create : List.of(false, true)) {
            var store = new FakeDeviceKeyStore(); if (!create) { store.seed(new byte[32]); }
            store.signFault = fault;
            var replay = replay(established(new byte[32]));
            try (var result = create ? DeviceIdentityLifecycle.createNew(replay, store)
                    : DeviceIdentityLifecycle.loadExisting(replay, store)) {
                assertEquals(KEY_MATERIAL_INVALID, result.status());
                assertThrows(IllegalStateException.class, result::verificationCandidate);
            }
            assertEquals(1, store.closes); assertEquals(1, store.signs);
        }
    }
    @Test void malformedKeysAndBindingsNeverSign() throws Exception {
        for (byte[] publicKey : List.of(new byte[0], new byte[64], new byte[66], new byte[65],
                CryptoSupport.join(new byte[]{4}, new byte[64]))) {
            var store = new FakeDeviceKeyStore(); store.seed(new byte[32]); store.publicOverride = publicKey;
            try (var result = DeviceIdentityLifecycle.loadExisting(replay(established(new byte[32])), store)) {
                assertEquals(KEY_MATERIAL_INVALID, result.status());
            }
            assertEquals(0, store.signs); assertEquals(1, store.closes);
        }
        for (byte[] binding : new byte[][]{null, new byte[0], new byte[31], new byte[33]}) {
            var store = new FakeDeviceKeyStore(); store.seed(new byte[32]); store.binding = binding;
            try (var result = DeviceIdentityLifecycle.loadExisting(replay(established(new byte[32])), store)) {
                assertEquals(KEY_MATERIAL_INVALID, result.status());
            }
            assertEquals(0, store.signs); assertEquals(1, store.closes);
        }
    }
    @ParameterizedTest @EnumSource(FakeDeviceKeyStore.Fault.class)
    void storageFailureMatrixAndExplicitRecovery(FakeDeviceKeyStore.Fault fault) throws Exception {
        var store = new FakeDeviceKeyStore(); store.fault = fault;
        var replay = replay(established(new byte[32]));
        try (var result = DeviceIdentityLifecycle.createNew(replay, store)) {
            assertEquals(switch (fault) {
                case NONE -> CREATED_BOUND;
                case LOAD_IO -> KEY_STORAGE_UNAVAILABLE;
                case LOAD_INVALID -> KEY_MATERIAL_INVALID;
                default -> KEY_CREATION_INCOMPLETE;
            }, result.status());
        }
        assertEquals(fault == FakeDeviceKeyStore.Fault.LOAD_IO || fault == FakeDeviceKeyStore.Fault.LOAD_INVALID ? 0 : 1, store.creates);
        store.fault = FakeDeviceKeyStore.Fault.NONE;
        try (var load = DeviceIdentityLifecycle.loadExisting(replay, store)) {
            assertEquals(switch (fault) {
                case NONE, AFTER_COMMIT, COLLISION -> AVAILABLE_BOUND;
                default -> ABSENT;
            }, load.status());
        }
    }
    @Test void existingIdentityIsNeverReplacedAndHandlesClose() throws Exception {
        var store = new FakeDeviceKeyStore(); store.seed(new byte[32]);
        var replay = replay(established(new byte[32]));
        try (var result = DeviceIdentityLifecycle.createNew(replay, store)) { assertEquals(KEY_ALREADY_EXISTS, result.status()); }
        assertEquals(0, store.creates); assertEquals(0, store.signs); assertEquals(1, store.closes);
        var loaded = DeviceIdentityLifecycle.loadExisting(replay, store);
        loaded.close(); loaded.close();
        assertEquals(2, store.closes);
        assertThrows(IllegalStateException.class, loaded::publicKeyX963);
        assertThrows(IllegalStateException.class, () -> loaded.signSha256Ecdsa(new byte[0]));
        assertThrows(java.io.IOException.class, () -> store.createDurably(new byte[32]));
    }
    @Test void laterProviderAnomalyRevokesCapabilityAndPreservesCallerMessage() throws Exception {
        var store = new FakeDeviceKeyStore(); store.seed(new byte[32]);
        try (var result = DeviceIdentityLifecycle.loadExisting(replay(established(new byte[32])), store)) {
            store.signFault = FakeDeviceKeyStore.SignFault.MUTATE;
            byte[] message = new byte[]{1, 2, 3};
            assertThrows(GeneralSecurityException.class, () -> result.signSha256Ecdsa(message));
            assertArrayEquals(new byte[]{1, 2, 3}, message);
            assertThrows(IllegalStateException.class, result::verificationCandidate);
        }
        assertEquals(1, store.closes);
    }
    @Test void nullAndWrongWidthFailBeforeBackendMutationOrProviderUse() throws Exception {
        var store = new FakeDeviceKeyStore();
        assertThrows(NullPointerException.class, () -> store.createDurably(null));
        for (int width : new int[]{0, 31, 33}) {
            assertThrows(IllegalArgumentException.class, () -> store.createDurably(new byte[width]));
        }
        assertEquals(0, store.creates);
        var replay = replay(established(new byte[32]));
        assertThrows(NullPointerException.class, () -> DeviceIdentityLifecycle.loadExisting(null, store));
        assertThrows(NullPointerException.class, () -> DeviceIdentityLifecycle.createNew(replay, null));
        try (var handle = store.createDurably(new byte[32])) {
            assertThrows(NullPointerException.class, () -> handle.signSha256Ecdsa(null));
            assertEquals(0, store.signs);
            byte[] b = handle.vaultBinding(); b[0] = 1; assertEquals(0, handle.vaultBinding()[0]);
            byte[] k = handle.publicKeyX963(); k[0] = 0; assertEquals(4, handle.publicKeyX963()[0]);
        }
        try (var result = DeviceIdentityLifecycle.loadExisting(replay, store)) {
            int signs = store.signs;
            assertThrows(NullPointerException.class, () -> result.signSha256Ecdsa(null));
            assertEquals(signs, store.signs);
        }
    }
}
