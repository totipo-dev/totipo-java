package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.file.Path;

/** Explicit platform capability required before acknowledging durable storage.
 * Implementations must fail if they cannot provide the requested barrier.
 * Newly written temporary files are forced through their existing channel instead.
 * The caller owns the capability; storage handles do not close it. */
public interface StorageDurability {
    /** Persist the containing directory's namespace changes. */
    void syncDirectory(Path directory) throws IOException;
    /** Persist pre-existing file bytes before adopting them as durable. */
    void syncExistingFile(Path file) throws IOException;
}
