package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;

/** Thread-confined channel owning one verified regular readable descriptor. */
final class LinuxReadChannel implements ReadableByteChannel {
    private final LinuxLibc libc;
    private final LinuxFd fd;
    LinuxReadChannel(LinuxLibc libc, LinuxFd fd) { this.libc = libc; this.fd = fd; }
    @Override public int read(ByteBuffer dst) throws IOException { fd.number(); return libc.read(fd, dst); }
    @Override public boolean isOpen() { return fd.isOpen(); }
    @Override public void close() throws IOException { fd.close(); }
}
