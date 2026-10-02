package org.totipo.format;

import org.totipo.RevisionId;
import org.totipo.TokenHead;
import org.totipo.testing.MemoryVault;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/** Hostile-but-valid provider fixture: cross-token references are unresolved graph edges. */
public final class ApplicationCausalFixture {
    private ApplicationCausalFixture() { }
    public static RevisionId add(MemoryVault store, org.totipo.TokenId token, TokenHead parent) {
        try (var unlocked = new VaultUnlocker().unlock(store.bootstrap, "password".getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            byte[] root = unlocked.root();
            var secret = new SecurityBytes(new byte[]{1, 2, 3}, 3);
            try {
                var value = new TokenValue(1, "fixture", "", new TokenValue.Credential(1, 6, 30, secret));
                var plan = TokenPublicationPlan.planAssertion(new TokenId(HexFormat.of().parseHex(token.hex())),
                        List.of(ObjectId.fromFilename(parent.revision().hex())), value,
                        new TokenMetadata(Optional.empty(), Optional.empty()), root);
                var stage = plan.stages().get(0);
                byte[] semantic = TokenWriter.write(stage.token());
                try {
                    var envelope = V1EnvelopeWriter.seal(root, semantic);
                    store.objects.put(envelope.id().filename(), envelope.bytes());
                    return new RevisionId(envelope.id().filename());
                } finally { Arrays.fill(semantic, (byte) 0); }
            } finally { Arrays.fill(root, (byte) 0); secret.clear(); }
        }
    }
}
