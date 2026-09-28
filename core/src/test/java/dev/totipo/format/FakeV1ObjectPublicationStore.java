package dev.totipo.format;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/** Contract model only: in-memory acknowledgements are not crash durability evidence. */
final class FakeV1ObjectPublicationStore implements V1ObjectPublicationStore {
    enum Fault { NONE, BEFORE_INSTALL, AFTER_INSTALL, DIFFERENT, WRONG_SIZE, UNSAFE }
    private final Map<ObjectId, byte[]> objects = new HashMap<>();
    Fault fault = Fault.NONE;
    boolean closed;
    int calls;
    Runnable afterSnapshot = () -> {};
    void seed(ObjectId id, byte[] bytes) { objects.put(id, bytes.clone()); }
    byte[] get(ObjectId id) { var bytes = objects.get(id); return bytes == null ? null : bytes.clone(); }
    Map<ObjectId, byte[]> snapshot() {
        var result = new HashMap<ObjectId, byte[]>();
        objects.forEach((id, bytes) -> result.put(id, bytes.clone()));
        return result;
    }
    @Override public PublicationResult publishDurably(ObjectId id, byte[] bytes) throws IOException {
        Objects.requireNonNull(id); Objects.requireNonNull(bytes);
        if (closed) { throw new IOException("Closed"); }
        if (bytes.length != 1024) { throw new IllegalArgumentException("Object width"); }
        byte[] exact = bytes.clone();
        calls++; afterSnapshot.run();
        if (fault == Fault.BEFORE_INSTALL) { throw new IOException("Pre-install failure"); }
        if (fault == Fault.UNSAFE) { throw new IOException("Unsafe existing target"); }
        if (fault == Fault.DIFFERENT) { byte[] wrong = exact.clone(); wrong[0] ^= 1; objects.putIfAbsent(id, wrong); }
        if (fault == Fault.WRONG_SIZE) { objects.putIfAbsent(id, new byte[1023]); }
        byte[] old = objects.get(id);
        if (old != null) {
            if (!Arrays.equals(exact, old)) { throw new IOException("Collision"); }
            return PublicationResult.ALREADY_PRESENT_EXACT;
        }
        objects.put(id, exact);
        if (fault == Fault.AFTER_INSTALL) { throw new IOException("Ambiguous acknowledgement"); }
        return PublicationResult.PUBLISHED_NEW;
    }
    @Override public void close() { closed = true; }
}
