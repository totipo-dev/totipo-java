package dev.totipo.storage.nio;

import dev.totipo.format.ObjectId;
import dev.totipo.format.V1ObjectPublicationStore;
import java.io.IOException;
import java.nio.file.*;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class NioApplicationPublicationTest {
    @TempDir Path root;
    @Test void exactExistingApplicationAcknowledgementReestablishesDirectoryBarriers() throws Exception {
        var id = ObjectId.fromFilename("ab".repeat(32)); var bytes = new byte[1024];
        var calls = new ArrayList<Path>();
        try (var store = new NioApplicationPublication(root, directory -> calls.add(directory))) {
            assertEquals(V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW, store.publish(id, bytes));
            calls.clear();
            assertEquals(V1ObjectPublicationStore.PublicationResult.ALREADY_PRESENT_EXACT, store.publish(id, bytes));
            assertEquals(java.util.List.of(root.resolve("objects-v1"), root), calls);
        }
    }
    @Test void failedExactExistingBarrierCannotAcknowledgeSaved() throws Exception {
        var id = ObjectId.fromFilename("ab".repeat(32)); var bytes = new byte[1024];
        try (var initial = new NioApplicationPublication(root, directory -> {})) { initial.publish(id, bytes); }
        try (var retry = new NioApplicationPublication(root, directory -> { throw new IOException("Lost force acknowledgement"); })) {
            assertThrows(IOException.class, () -> retry.publish(id, bytes));
            assertArrayEquals(bytes, Files.readAllBytes(root.resolve("objects-v1").resolve(id.filename())));
        }
    }
}
