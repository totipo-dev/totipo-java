package org.totipo.storage.nio;

import org.totipo.spi.StoreFailure;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;

/** Positive structural safety evidence; ordinary I/O errors remain unavailable. */
final class NioNamespace extends IOException {
    private static final long serialVersionUID = 1L;
    NioNamespace(String reason) { super(reason); }

    /** Retain the legacy exclusive-create exception contract for alias collisions. */
    static final class Collision extends FileAlreadyExistsException {
        private static final long serialVersionUID = 1L;
        Collision(String path) { super(path); }
    }
    static StoreFailure failure(Exception failure) {
        if (failure instanceof NioNamespace || failure instanceof Collision) return StoreFailure.UNSAFE_NAMESPACE;
        return failure instanceof UnsupportedOperationException ? StoreFailure.UNSUPPORTED : StoreFailure.UNAVAILABLE;
    }
}
