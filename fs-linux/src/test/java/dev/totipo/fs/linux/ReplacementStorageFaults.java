package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Test-only bridge: callbacks interleave namespace actors with real Linux operations. */
public class ReplacementStorageFaults extends LinuxVaultBootstrapStorage.Operations {
    public interface Action { void run() throws IOException; }
    public Action afterLink = () -> {}, beforeExchange = () -> {}, afterExchange = () -> {},
            afterPostSync = () -> {}, afterDirectory = () -> {}, beforeUnlink = () -> {};
    public String fail = "";
    public int exchangeErrno, syncs, exchanges, unlinks, names;
    public boolean deterministicNames;
    public final List<String> events = new ArrayList<>();
    public String linkedName;
    LinuxStatx stageIdentity;
    public LinuxVaultBootstrapStorage open(Path root) throws IOException {
        return LinuxVaultBootstrapStorage.open(root, this);
    }
    public void unsupportedExchange() { exchangeErrno = LinuxAbi.EINVAL; }
    void event(String name) throws IOException {
        events.add(name); if (fail.equals(name)) throw new IOException("injected " + name);
    }
    public static String name(int index) { return ".totipo-vault-rewrap-" + String.format("%032x", index) + ".tmp"; }
    @Override String replacementName() { return deterministicNames ? name(names++) : super.replacementName(); }
    @Override void syncStage(LinuxLibc libc, LinuxFd fd) throws IOException {
        stageIdentity = libc.stat(fd); event(++syncs == 1 ? "stage-sync" : "post-exchange-sync");
        super.syncStage(libc, fd);
        if (syncs > 1) afterPostSync.run();
    }
    @Override void linkReplacement(LinuxLibc libc, LinuxFd stage, LinuxFd root, String name) throws IOException {
        event("private-link"); super.linkReplacement(libc, stage, root, name);
        linkedName = name; afterLink.run();
    }
    @Override void exchange(LinuxLibc libc, LinuxFd root, String name) throws IOException {
        beforeExchange.run(); exchanges++; event("exchange");
        if (exchangeErrno != 0) throw new LinuxLibc.NativeFailure(exchangeErrno);
        super.exchange(libc, root, name); afterExchange.run();
    }
    @Override void unlink(LinuxLibc libc, LinuxFd root, String name) throws IOException {
        beforeUnlink.run(); unlinks++; event("unlink"); super.unlink(libc, root, name);
    }
    @Override void syncDirectory(LinuxLibc libc, LinuxFd root) throws IOException {
        event("directory-sync"); super.syncDirectory(libc, root); afterDirectory.run();
    }
}
