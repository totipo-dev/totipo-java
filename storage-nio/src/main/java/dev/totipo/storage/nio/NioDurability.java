package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Pure-Java runtime capability for containing-directory persistence.
 * Successful return means the provider accepted the requested directory-channel force
 * operation; unsupported providers fail rather than being treated as durable.
 * Java SE does not guarantee directory fsync semantics on every provider.
 */
public final class NioDurability implements StorageDurability {
    @Override public void syncDirectory(Path directory) throws IOException {
        try {
            NioFiles.directory(directory);
            try (FileChannel channel = FileChannel.open(directory,
                    StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
                channel.force(true);
            }
        } catch (IOException | UnsupportedOperationException | IllegalArgumentException | SecurityException e) {
            throw new IOException("Directory-channel force unavailable for " + directory, e);
        }
    }
}
