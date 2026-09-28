package dev.totipo.format;

import static org.junit.jupiter.api.Assertions.*;
import static dev.totipo.format.ProvenanceStatus.*;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class LocalIdentityProvenanceTest {
    @Test void localKeyReevaluatesOnlyMatchingAttributionWithoutChangingAssertion() throws Exception {
        var fixture = ProvenanceTest.token(); byte[] root = ProvenanceTest.root(fixture);
        var store = new FakeDeviceKeyStore();
        var memory = new VaultBindingStore.Binding(VaultBindingStore.State.PRESENT, CryptoSupport.hmac(root,CryptoSupport.ascii("totipo/v1/local-vault-binding")));
        byte[] journal = memory.bytes();
        try (var local = DeviceIdentityLifecycle.createNew(memory, store)) {
            // Test-only signed assertion construction, never a production TOKEN writer.
            byte[] semantic = TlvTestBytes.replace(fixture.semanticBytes(), 0x0102, local.deviceId());
            var unsigned = ProvenanceTest.valid(semantic, root).unsignedSemantic();
            byte[] input = P256.signatureInput(root, 1, unsigned);
            byte[] signature;
            try { signature = local.signSha256Ecdsa(input); }
            finally { Arrays.fill(input, (byte) 0); }
            semantic = TlvTestBytes.replace(semantic, 0xff01, signature);
            var valid = ProvenanceTest.valid(semantic, root);
            var bad = ProvenanceTest.valid(TlvTestBytes.replace(semantic, 0xff01,
                    new byte[]{0x30, 6, 2, 1, 1, 2, 1, 1}), root);
            var unrelated = ProvenanceTest.valid(fixture.semanticBytes(), root);
            var assertions = List.of(valid, bad, unrelated);
            var plain = valid.plaintext(); var originalUnsigned = valid.unsignedSemantic();
            var empty = VerificationKeyMaterial.keys();
            for (var a : assertions) { assertEquals(UNRESOLVED, ProvenanceEvaluator.evaluate(a, root, empty)); }
            assertEquals(List.of(VERIFIED, REJECTED, UNRESOLVED),
                    ProvenanceEvaluator.withLocalIdentity(assertions, root, empty, local));
            assertEquals(List.of(VERIFIED, REJECTED, VERIFIED), ProvenanceEvaluator.withLocalIdentity(
                    assertions, root, VerificationKeyMaterial.keys(ProvenanceTest.key(fixture)), local));
            assertSame(plain, valid.plaintext()); assertArrayEquals(originalUnsigned, valid.unsignedSemantic());
            assertArrayEquals(journal, memory.bytes());
            byte[] otherRoot = root.clone(); otherRoot[0] ^= 1;
            assertThrows(IllegalArgumentException.class,
                    () -> ProvenanceEvaluator.withLocalIdentity(assertions, otherRoot, empty, local));
        }
    }
}
