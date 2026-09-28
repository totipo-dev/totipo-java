package dev.totipo.format;

import dev.totipo.storage.nio.*;
import dev.totipo.platform.linux.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;

/** Deliberate halt at the actual TOKEN publication/knowledge boundaries. */
public final class TokenPublicationCrashProcess {
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Path sync = Path.of(args[1]), local = Path.of(args[2]);
        var memory = LinuxSecurityMemoryStorage.open(local);
        var session = SecurityMemorySession.open(memory);
        var keys = LinuxDeviceProvenanceKeyStore.open(local);
        var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys);
        var publisher = NioV1ObjectPublicationStore.open(sync, LinuxDurability.open());
        var discovery = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
        var value = new TokenValue(1, "", "", new TokenValue.Credential(1, 6, 30, new SecurityBytes(new byte[]{1}, 1)));
        InitialTokenPublication.Receipt initial = mode.equals("update") ? InitialTokenPublication.publish(ROOT,
                () -> new InitialDeviceAdvertisement.Context(session, discovery.discoveryState(), 0),
                identity, value, new byte[8], publisher, List.of()).receipt() : null;
        int expectedKnowledge = initial == null ? 0 : 1;
        var store = new V1ObjectPublicationStore() {
            public PublicationResult publishDurably(ObjectId id, byte[] bytes) throws IOException {
                if (session.knowledge().size() != expectedKnowledge) throw new AssertionError("graph before publication");
                var result = publisher.publishDurably(id, bytes);
                System.out.println(id.filename()); System.out.flush();
                if (mode.equals("pregraph") || mode.equals("update")) Runtime.getRuntime().halt(0);
                return result;
            }
            public void close() throws IOException { publisher.close(); }
        };
        if (initial != null) {
            var graph = new GraphTopology(session.knowledge());
            var bytes = java.nio.file.Files.readAllBytes(sync.resolve("objects-v1").resolve(initial.objectId().filename()));
            var readable = new CurrentReadableValues(graph, List.of(ReadableTokenValue.supported(AssertionValidator.validate(
                    EnvelopeReader.open(initial.objectId().filename(), bytes, ROOT)).object())));
            TokenUpdatePublication.publish(ROOT, () -> new TokenUpdatePublication.Context(
                    new InitialDeviceAdvertisement.Context(session, discovery.discoveryState(), 0), graph, readable),
                    identity, initial.tokenId(), value, new byte[8], TokenUpdatePublication.Intent.ORDINARY, store, List.of());
            throw new AssertionError("Expected halt after update publication");
        }
        var result = InitialTokenPublication.publish(ROOT,
                () -> new InitialDeviceAdvertisement.Context(session, discovery.discoveryState(), 0),
                identity, value, new byte[8], store, List.of());
        if (result.status() != InitialTokenPublication.Status.PUBLISHED_AND_REMEMBERED_DEVICE_REQUIRED)
            throw new AssertionError(result.status());
        Runtime.getRuntime().halt(0);
    }
}
