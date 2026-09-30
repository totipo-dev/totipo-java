package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/** Application Saved requires a durability acknowledgement even after an ambiguous earlier install. */
final class NioApplicationPublication implements V1ObjectPublicationStore {
    private final NioV1ObjectPublicationStore delegate;
    private final Path root;
    private final StorageDurability durability;
    NioApplicationPublication(Path root, StorageDurability durability) throws IOException {
        this.root = root; this.durability = durability;
        delegate = NioV1ObjectPublicationStore.open(root, durability);
    }
    @Override public PublicationResult publish(ObjectId id, byte[] bytes) throws IOException {
        var result = delegate.publish(id, bytes);
        if (result == PublicationResult.ALREADY_PRESENT_EXACT) {
            Path directory = NioFiles.findExactDirectChild(root, "objects-v1")
                    .orElseThrow(() -> new IOException("Canonical namespace unavailable"));
            NioFiles.directory(directory);
            Path object = NioFiles.findExactDirectChild(directory, id.filename())
                    .orElseThrow(() -> new IOException("Canonical object unavailable"));
            NioFiles.regular(object);
            try (var channel = FileChannel.open(object, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                channel.force(true);
            }
            durability.syncDirectory(directory);
            durability.syncDirectory(root);
        }
        return result;
    }
    @Override public void close() { delegate.close(); }
}
