package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;

import dev.totipo.conformance.VectorCaseLoader;
import dev.totipo.conformance.VectorCaseLoader.Node;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

/** Shared executable vault consumer. FORMAT.md defines workflow bytes as symbolic. */
final class VaultVectorChecks {
    private VaultVectorChecks() {}
    private static void fields(Node node, String... names) { assertEquals(Set.of(names), node.fieldNames()); }

    static void check(VectorCaseLoader.Case vector) {
        assertEquals("PASS", vector.expected());
        fields(vector.data(), "format", "id", "operation", "expected", "workflow");
        assertEquals("workflow", vector.data().field("operation").string());
        var fixture = vector.data().field("workflow");
        fields(fixture, "action", "kind", "existing_hex", "intended_hex", "base_hex", "readable",
                "complete", "durable", "orphan_objects", "parents_available", "result");
        String action = fixture.field("action").string();
        assertTrue(Set.of("create", "replace").contains(action), "Unknown vault action");
        String kind = fixture.field("kind").string();
        assertTrue(Set.of("absent", "regular").contains(kind), "Unknown vault kind");
        byte[] base = fixture.field("base_hex").hex(), current = fixture.field("existing_hex").hex();
        assertArrayEquals(new byte[0], fixture.field("intended_hex").hex()); // Generated complete wrapper, not literal empty bytes.
        assertTrue(fixture.field("complete").bool());
        assertFalse(fixture.field("parents_available").bool()); // No TOKEN graph is supplied or consulted.
        boolean orphans = fixture.field("orphan_objects").bool();
        byte[] orphan = orphans ? new byte[]{11, 22, 33} : new byte[0];
        byte[] savedOrphan = orphan.clone(); // Storage SPI exposes no object discovery/deletion operation.
        boolean readable = fixture.field("readable").bool(), durable = fixture.field("durable").bool();
        String expected = fixture.field("result").string();
        assertTrue(Set.of("CREATED", "REPLACED", "STALE", "FAILED").contains(expected), "Unknown verdict");
        for (boolean residue : durable ? List.of(false) : List.of(false, true)) {
            var store = new VaultTestStore(); store.durable = durable; store.installOnFailure = residue;
            var lifecycle = new VaultLifecycle(new VaultBootstrapWriter(), new VaultUnlocker(), bytes -> Arrays.fill(bytes, (byte) 7));
            byte[] password = CryptoSupport.ascii("vault vector");
            String actual;
            if (action.equals("create")) {
                assertArrayEquals(new byte[0], base); assertArrayEquals(new byte[0], current);
                assertFalse(readable);
                store.canonical = kind.equals("absent") ? null : current.clone();
                store.unreadable = !kind.equals("absent") && !readable;
                try (var result = lifecycle.createNew(store, password)) {
                    actual = result.status().name();
                    if (result.status() == VaultLifecycle.CreationStatus.CREATED) {
                        byte[] root = new byte[32]; Arrays.fill(root, (byte) 7);
                        assertArrayEquals(root, result.root());
                        assertArrayEquals(CryptoSupport.vaultFingerprint(root), result.fingerprint());
                    }
                }
                assertEquals(kind.equals("absent") ? 1 : 0, store.installs);
                if (kind.equals("absent")) assertEquals(durable || residue, store.canonical != null);
            } else {
                assertEquals("regular", kind); assertFalse(orphans);
                assertTrue(base.length > 0);
                // Injectively lift abstract BASE/CURRENT labels into structurally valid wrappers.
                // The first observation authenticates BASE; the second represents fixture CURRENT.
                byte[] wrapper = wrapper(base, password);
                byte[] observed = wrapper(current, password);
                assertEquals(Arrays.equals(base, current), Arrays.equals(wrapper, observed));
                store.canonical = wrapper.clone();
                store.beforeRead = () -> {
                    if (store.reads == 2) { store.canonical = observed.clone(); store.unreadable = !readable; }
                };
                var result = lifecycle.changePassword(store, password, CryptoSupport.ascii("next"));
                actual = result == VaultLifecycle.PasswordChangeResult.SUCCESS ? "REPLACED" : result.name();
                boolean mayReplace = readable && Arrays.equals(base, current);
                assertEquals(mayReplace ? 1 : 0, store.replacements);
                assertEquals(2, store.reads);
                if (!mayReplace || (!durable && !residue)) assertArrayEquals(observed, store.canonical);
                if (mayReplace && (durable || residue)) assertArrayEquals(store.staged, store.canonical);
            }
            assertEquals(expected, actual, vector.context());
            assertArrayEquals(savedOrphan, orphan);
            assertEquals(store.stages, store.closes);
        }
    }

    private static byte[] wrapper(byte[] label, byte[] password) {
        // Domain-separated deterministic fixture material; production always uses CSPRNG draws.
        byte[] salt = Arrays.copyOf(CryptoSupport.sha256(new byte[]{1}, label), 16);
        byte[] nonce = Arrays.copyOf(CryptoSupport.sha256(new byte[]{2}, label), 12);
        return new VaultBootstrapWriter().encode(password, new byte[32], salt, nonce);
    }
}
