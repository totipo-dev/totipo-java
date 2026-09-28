package dev.totipo.fs.linux;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.*;
public class ReplacementStorageFaults extends LinuxVaultBootstrapStorage.Operations {
    public interface Action { void run() throws IOException; }
    public Action afterStage = () -> {}, beforeMove = () -> {}, afterMove = () -> {}, afterDirectory = () -> {};
    public String fail = "";
    public int moves;
    public boolean unsupported;
    public LinuxVaultBootstrapStorage open(Path root) throws IOException { return LinuxVaultBootstrapStorage.open(root, this); }
    @Override void syncStage(FileChannel channel) throws IOException {
        if (fail.equals("stage-sync")) throw new IOException("force failed");
        super.syncStage(channel); afterStage.run();
    }
    @Override void move(Path temp, Path target) throws IOException {
        beforeMove.run(); moves++;
        if (unsupported) throw new AtomicMoveNotSupportedException(temp.toString(), target.toString(), "injected");
        if (fail.equals("move")) throw new IOException("move failed");
        super.move(temp, target); afterMove.run();
    }
    @Override void syncDirectory(Path root) throws IOException {
        if (fail.equals("directory-sync")) throw new IOException("directory failed");
        super.syncDirectory(root); afterDirectory.run();
    }
}
