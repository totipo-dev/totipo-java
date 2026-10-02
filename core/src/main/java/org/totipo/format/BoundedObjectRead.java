package org.totipo.format;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.util.Arrays;

/** Reads at most 1025 bytes; a full buffer already proves oversize. Never uses metadata. */
final class BoundedObjectRead {
    private BoundedObjectRead() {}

    static byte[] read(ReadableByteChannel channel) throws IOException {
        var buffer = ByteBuffer.allocate(EnvelopeReader.OBJECT_BYTES + 1);
        while (buffer.hasRemaining()) {
            int count = channel.read(buffer);
            if (count < 0) { break; }
            // A blocking regular-file handle should progress or report EOF. Do not retry
            // a faulty/nonblocking provider indefinitely; required bytes are unavailable.
            if (count == 0) { throw new IOException("Object read made no progress"); }
        }
        return Arrays.copyOf(buffer.array(), buffer.position());
    }
}
