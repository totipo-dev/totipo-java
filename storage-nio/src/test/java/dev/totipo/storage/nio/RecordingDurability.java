package dev.totipo.storage.nio;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Test orchestration only; makes no claim of physical persistence. */
final class RecordingDurability implements StorageDurability {
    record Event(String operation, Path path) {}
    final List<Event> events = new ArrayList<>();
    String fail = "";
    @FunctionalInterface interface Action { void run(Event event) throws IOException; }
    Action action = event -> {};
    private void record(String operation, Path path) throws IOException {
        var event = new Event(operation, path);
        events.add(event);
        action.run(event);
        if (fail.equals(operation)) throw new IOException("injected " + operation);
    }
    @Override public void syncDirectory(Path path) throws IOException { record("directory", path); }
    @Override public void syncExistingFile(Path path) throws IOException { record("existing", path); }
}
