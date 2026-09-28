package dev.totipo.fs.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;

/** Test-only access to the package-private low-level seam, including from core's test package. */
public final class StorageFaults extends LinuxSecurityMemoryStorage.Operations {
    public boolean failForce;
    public boolean partialWrite;
    public boolean failWrite;
    public int forces;
    public int writes;
    public final java.util.List<String> adoption = new java.util.ArrayList<>();
    @Override void syncJournal(Path path) throws IOException {
        super.syncJournal(path); adoption.add("journal");
    }
    @Override void syncDirectory(Path directory) throws IOException {
        super.syncDirectory(directory); adoption.add("directory");
    }
    public LinuxSecurityMemoryStorage open(Path directory) throws IOException {
        return LinuxSecurityMemoryStorage.open(directory,this);
    }
    @Override void force(FileChannel channel) throws IOException {
        forces++; if(failForce) throw new IOException("injected force"); super.force(channel);
    }
    @Override int write(FileChannel channel,ByteBuffer bytes,long offset) throws IOException {
        writes++;
        if (failWrite) throw new IOException("injected before journal write");
        if(partialWrite) {
            var prefix=bytes.slice(); prefix.limit(Math.min(55,prefix.remaining()));
            channel.write(prefix,offset); throw new IOException("injected partial write");
        }
        return super.write(channel,bytes,offset);
    }
}
