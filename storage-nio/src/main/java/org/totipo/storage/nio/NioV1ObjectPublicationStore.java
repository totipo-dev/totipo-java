package org.totipo.storage.nio;

import org.totipo.format.ObjectId;
import org.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.file.Path;

/** Legacy protocol adapter over the shared opaque NIO publication engine. */
public final class NioV1ObjectPublicationStore implements V1ObjectPublicationStore {
    private final NioObjectStorage delegate;
    public static NioV1ObjectPublicationStore open(Path root, StorageDurability durability) throws IOException {
        return open(root, new Operations(durability));
    }
    static NioV1ObjectPublicationStore open(Path root, Operations operations) throws IOException {
        return new NioV1ObjectPublicationStore(NioObjectStorage.open(root, operations));
    }
    private NioV1ObjectPublicationStore(NioObjectStorage delegate) { this.delegate = delegate; }
    static class Operations extends NioObjectStorage.Operations {
        Operations(StorageDurability durability) { super(durability); }
        byte[] readExisting(Path target, String point) throws IOException { return super.readExisting(target, point, 1025); }
        @Override byte[] readExisting(Path target, String point, int limit) throws IOException {
            return readExisting(target, point);
        }
    }
    @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
        if (bytes.length != 1024) throw new IllegalArgumentException("EXACT_1024_BYTES_REQUIRED");
        return delegate.publish(id.filename(), bytes, false)
                ? PublicationResult.PUBLISHED_NEW : PublicationResult.ALREADY_PRESENT_EXACT;
    }
    @Override public void close() { delegate.close(); }
}
