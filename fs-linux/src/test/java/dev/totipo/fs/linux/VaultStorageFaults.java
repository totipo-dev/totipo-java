package dev.totipo.fs.linux;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;
public final class VaultStorageFaults extends LinuxVaultBootstrapStorage.Operations {
    public interface Action { void run() throws IOException; }
    public Action beforeStage = () -> {}, beforeLink = () -> {}, afterDirectory = () -> {};
    public String fail = "";
    public int writeLimit = Integer.MAX_VALUE, stageSyncs;
    public final List<String> events = new ArrayList<>();
    public LinuxVaultBootstrapStorage open(Path root) throws IOException { return LinuxVaultBootstrapStorage.open(root, this); }
    private void event(String name) throws IOException { events.add(name); if (fail.equals(name)) throw new IOException("injected " + name); }
    @Override Path temporary(Path root) throws IOException { beforeStage.run(); event("temporary"); return super.temporary(root); }
    @Override int write(FileChannel channel, ByteBuffer bytes) throws IOException {
        event("write"); if (fail.equals("zero")) return 0;
        int limit = bytes.limit(); bytes.limit(Math.min(limit, bytes.position() + writeLimit));
        try { int n = super.write(channel, bytes); if (fail.equals("partial-write")) throw new IOException("partial"); return n; }
        finally { bytes.limit(limit); }
    }
    @Override void syncStage(FileChannel channel) throws IOException { stageSyncs++; event("stage-sync"); super.syncStage(channel); }
    @Override void link(Path target, Path temp) throws IOException { beforeLink.run(); event("link"); super.link(target, temp); }
    @Override void syncDirectory(Path root) throws IOException { event("directory-sync"); super.syncDirectory(root); afterDirectory.run(); }
}
