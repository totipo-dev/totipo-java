package dev.totipo.format;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Exact-byte SPI simulation; provides no filesystem or physical persistence evidence. */
final class PublicationTestStore implements V1ObjectPublicationStore {
    final Map<ObjectId, byte[]> objects = new LinkedHashMap<>();
    final List<PublicationResult> acknowledgements = new ArrayList<>();
    int calls;
    int failCall = -1;
    boolean installOnFailure;
    boolean closed;
    @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
        if (closed) throw new IOException("Closed store");
        if (bytes.length != 1024) throw new IllegalArgumentException("Exact object required");
        calls++;
        byte[] owned = bytes.clone();
        byte[] old = objects.get(id);
        if (old != null && !Arrays.equals(old, owned)) throw new IOException("Non-exact target");
        if (calls == failCall) {
            if (installOnFailure) objects.putIfAbsent(id, owned);
            throw new IOException("Ambiguous publication");
        }
        var result = old == null ? PublicationResult.PUBLISHED_NEW : PublicationResult.ALREADY_PRESENT_EXACT;
        objects.putIfAbsent(id, owned);
        acknowledgements.add(result);
        return result;
    }
    @Override public void close() { closed = true; }
}
