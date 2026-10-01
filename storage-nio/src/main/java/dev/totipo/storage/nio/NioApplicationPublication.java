package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.file.Path;

/** Application Saved requires a durability acknowledgement even after an ambiguous earlier install. */
final class NioApplicationPublication implements V1ObjectPublicationStore {
    private final NioObjectStorage delegate;
    NioApplicationPublication(Path root, StorageDurability durability) throws IOException {
        delegate = NioObjectStorage.open(root, durability);
    }
    @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
        if (bytes.length != 1024) throw new IllegalArgumentException("EXACT_1024_BYTES_REQUIRED");
        return delegate.publish(id.filename(), bytes, true)
                ? PublicationResult.PUBLISHED_NEW : PublicationResult.ALREADY_PRESENT_EXACT;
    }
    @Override public void close() { delegate.close(); }
}
