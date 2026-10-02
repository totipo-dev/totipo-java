package org.totipo.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Publishes in order; failure stops immediately and leaves acknowledged stages intact. */
final class TokenPublisher {
    private TokenPublisher() {}

    /** Return means every stage was acknowledged locally. The caller owns the store and retry. */
    static List<V1ObjectPublicationStore.PublicationResult> publish(TokenPublicationPlan plan,
            byte[] root, V1ObjectPublicationStore store) throws IOException {
        var acknowledgements = new ArrayList<V1ObjectPublicationStore.PublicationResult>();
        for (var stage : plan.stages()) {
            byte[] semantic = TokenWriter.write(stage.token());
            try {
                var object = V1EnvelopeWriter.seal(root, semantic);
                if (!object.id().equals(stage.objectId())) {
                    throw new IllegalArgumentException("Publication root does not match plan");
                }
                var result = store.publish(stage.objectId(), object.bytes());
                if (result == null) throw new IOException("Publication not acknowledged");
                acknowledgements.add(result);
            } finally {
                Arrays.fill(semantic, (byte) 0);
            }
        }
        return List.copyOf(acknowledgements);
    }
}
