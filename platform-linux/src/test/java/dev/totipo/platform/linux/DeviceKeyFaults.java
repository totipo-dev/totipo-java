package dev.totipo.platform.linux;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Path;
import java.security.*;
import java.util.*;

/** Test-only bridge; no production fault API. */
public final class DeviceKeyFaults extends LinuxDeviceProvenanceKeyStore.Operations {
    public interface Action { void run(String boundary) throws IOException; }
    public String fail = "";
    public Action action = name -> {};
    public int generations, writeLimit = Integer.MAX_VALUE;
    public final List<String> events = new ArrayList<>();
    ByteBuffer observed;
    KeyPair pair;
    public LinuxDeviceProvenanceKeyStore open(Path root) throws IOException {
        return LinuxDeviceProvenanceKeyStore.open(root, this);
    }
    @Override KeyPair generate() throws GeneralSecurityException {
        generations++; return pair == null ? super.generate() : pair;
    }
    @Override void boundary(String name) throws IOException {
        events.add(name); action.run(name);
        if (name.equals(fail)) throw new IOException("injected " + name);
    }
    @Override int write(java.nio.channels.FileChannel channel, ByteBuffer bytes) throws IOException {
        observed = bytes.duplicate(); observed.clear();
        boundary("write"); if (fail.equals("zero")) return 0;
        int limit = bytes.limit(); bytes.limit(Math.min(limit, bytes.position() + writeLimit));
        try {
            int result = super.write(channel, bytes);
            if (fail.equals("partial-write")) throw new IOException("partial write");
            return result;
        } finally { bytes.limit(limit); }
    }
}
