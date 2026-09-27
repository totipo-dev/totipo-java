package dev.totipo.fs.linux;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.channels.ClosedChannelException;

/** Confined owner: invalidate before the single close attempt; never expose publicly. */
final class LinuxFd implements Closeable {
    private final LinuxLibc libc;
    private int number;
    LinuxFd(LinuxLibc libc, int number) { this.libc = libc; this.number = number; }
    int number() throws ClosedChannelException {
        if (number < 0) { throw new ClosedChannelException(); } return number;
    }
    boolean isOpen() { return number >= 0; }
    Path procPath() throws IOException { return Path.of("/proc/self/fd/" + number()); }
    @Override public void close() throws IOException {
        if (number >= 0) { int owned = number; number = -1; libc.close(owned); }
    }
}
