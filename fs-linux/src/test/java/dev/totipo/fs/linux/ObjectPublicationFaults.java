package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Test-only bridge; all nonfaulted operations use the production Linux implementation. */
public final class ObjectPublicationFaults extends LinuxV1ObjectPublicationStore.Operations {
    @FunctionalInterface public interface Action { void run(String point) throws IOException; }
    public Action action = point -> {};
    public String fail = "";
    public int writeLimit = 1024, temporaryErrno, linkErrno;
    public final List<String> events = new ArrayList<>();
    LinuxFd stage;
    public LinuxV1ObjectPublicationStore open(Path root) throws IOException {
        return LinuxV1ObjectPublicationStore.open(root, this);
    }
    @Override void at(String point) throws IOException {
        events.add(point); action.run(point);
        if (fail.equals(point)) { throw new IOException("injected " + point); }
    }
    @Override void mkdir(LinuxLibc libc, LinuxFd root) throws IOException {
        at("mkdir"); super.mkdir(libc, root);
    }
    @Override LinuxFd temporary(LinuxLibc libc, LinuxFd dir) throws IOException {
        if (temporaryErrno != 0) { throw new LinuxLibc.NativeFailure(temporaryErrno); }
        stage = super.temporary(libc, dir); return stage;
    }
    @Override int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException {
        at("write"); if (fail.equals("zero")) { return 0; }
        int limit = bytes.limit(); bytes.limit(Math.min(limit, bytes.position() + writeLimit));
        try { return super.write(libc, fd, bytes); } finally { bytes.limit(limit); }
    }
    @Override void link(LinuxLibc libc, LinuxFd stage, LinuxFd dir, String name) throws IOException {
        if (linkErrno != 0) { throw new LinuxLibc.NativeFailure(linkErrno); }
        super.link(libc, stage, dir, name);
    }
}
