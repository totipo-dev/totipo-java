package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.*;
public final class ObjectPublicationFaults extends NioV1ObjectPublicationStore.Operations {
    public ObjectPublicationFaults(StorageDurability durability) { super(durability); }
    @FunctionalInterface public interface Action { void run(String point) throws IOException; }
    public Action action = point -> {};
    public String fail = "";
    public int writeLimit = 1024;
    public final List<String> events = new ArrayList<>();
    public NioV1ObjectPublicationStore open(Path root) throws IOException { return NioV1ObjectPublicationStore.open(root, this); }
    @Override void at(String point) throws IOException { events.add(point); action.run(point); if (fail.equals(point)) throw new IOException("injected " + point); }
    @Override int write(FileChannel channel, ByteBuffer bytes) throws IOException {
        at("write"); if (fail.equals("zero")) return 0;
        int limit = bytes.limit(); bytes.limit(Math.min(limit, bytes.position() + writeLimit));
        try { return super.write(channel, bytes); } finally { bytes.limit(limit); }
    }
}
