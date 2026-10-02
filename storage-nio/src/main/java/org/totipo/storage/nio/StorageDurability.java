package org.totipo.storage.nio;

import java.io.IOException;
import java.nio.file.Path;

/** Injectable runtime capability for directory persistence.
 * Implementations must fail if they cannot provide the requested barrier.
 * Newly written temporary files are forced through their existing channel instead.
 * The caller owns the capability; storage handles do not close it. */
public interface StorageDurability {
    /** Request persistence of the containing directory's namespace changes.
     * Implementations document the guarantees their provider can offer. */
    void syncDirectory(Path directory) throws IOException;
}
