package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Test-only bridge to the fd operation seam; real operations run unless explicitly faulted. */
public final class VaultStorageFaults extends LinuxVaultBootstrapStorage.Operations {
    public interface Action { void run() throws IOException; }
    public Action beforeStage = () -> {}, beforeLink = () -> {}, afterDirectory = () -> {};
    public String fail = "";
    public int temporaryErrno, linkErrno, writeLimit = Integer.MAX_VALUE;
    public int stageSyncs;
    public final List<String> events = new ArrayList<>();
    LinuxStatx stagedIdentity;
    public LinuxVaultBootstrapStorage open(Path root) throws IOException {
        return LinuxVaultBootstrapStorage.open(root, this);
    }
    private void event(String name) throws IOException {
        events.add(name); if (fail.equals(name)) throw new IOException("injected " + name);
    }
    @Override LinuxFd temporary(LinuxLibc libc, LinuxFd root) throws IOException {
        beforeStage.run(); event("temporary");
        if (temporaryErrno != 0) throw new LinuxLibc.NativeFailure(temporaryErrno);
        return super.temporary(libc, root);
    }
    @Override int write(LinuxLibc libc, LinuxFd fd, ByteBuffer bytes) throws IOException {
        event("write"); if (fail.equals("zero")) return 0;
        int limit = bytes.limit(); bytes.limit(Math.min(limit, bytes.position() + writeLimit));
        try {
            int written = super.write(libc, fd, bytes);
            if (fail.equals("partial-write")) throw new IOException("injected after partial write");
            return written;
        } finally { bytes.limit(limit); }
    }
    @Override void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException {
        stagedIdentity = libc.stat(fd); event(++stageSyncs == 1 ? "stage-sync" : "post-link-sync");
        super.syncStage(libc, fd);
    }
    @Override void link(LinuxLibc libc, LinuxFd stage, LinuxFd root) throws IOException {
        beforeLink.run(); event("link");
        if (linkErrno != 0) throw new LinuxLibc.NativeFailure(linkErrno);
        super.link(libc, stage, root);
    }
    @Override void syncDirectory(LinuxLibc libc, LinuxFd root) throws IOException {
        event("directory-sync"); super.syncDirectory(libc, root); afterDirectory.run();
    }
}
