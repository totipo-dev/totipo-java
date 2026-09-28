package dev.totipo.format;

import dev.totipo.fs.linux.*;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import static dev.totipo.format.VaultStorageCrashProcess.ROOT;

/** Runtime.halt proves process-close independence in the running kernel, not power-loss durability. */
public final class ObjectPublicationCrashProcess {
    public static void main(String[] args) throws Exception {
        String mode = args[0]; Path sync = Path.of(args[1]), local = Path.of(args[2]);
        var faults = new ObjectPublicationFaults();
        faults.action = point -> {
            if (mode.equals("staged") && point.equals("before-link")
                    || mode.equals("linked") && point.equals("after-link")) Runtime.getRuntime().halt(0);
        };
        var publisher = faults.open(sync);
        if (mode.equals("open")) { publisher.close(); Runtime.getRuntime().halt(0); }
        var memory = LinuxSecurityMemoryStorage.open(local);
        var session = SecurityMemorySession.open(memory);
        var keys = LinuxDeviceProvenanceKeyStore.open(local);
        var identity = DeviceIdentityLifecycle.loadExisting(session.head(), keys);
        if (mode.equals("full") || mode.equals("pregraph")) {
            var discovery = DiscoveryCoordinator.discover(new NioDiscoverySource(sync), ROOT, session);
            var store = new V1ObjectPublicationStore() {
                public PublicationResult publishDurably(ObjectId id, byte[] bytes) throws IOException {
                    var result = publisher.publishDurably(id, bytes);
                    if (session.knowledge().size() != 0) throw new AssertionError("graph before publication");
                    System.out.println(id.filename()); System.out.flush();
                    if (mode.equals("pregraph")) Runtime.getRuntime().halt(0);
                    return result;
                }
                public void close() throws IOException { publisher.close(); }
            };
            var result = InitialDeviceAdvertisement.publish(ROOT,
                    () -> new InitialDeviceAdvertisement.Context(session, discovery.discoveryState(), 0),
                    identity, "Linux device", new byte[8], store);
            if (result.status() != InitialDeviceAdvertisement.Status.PUBLISHED_AND_REMEMBERED)
                throw new AssertionError(result.status());
            Runtime.getRuntime().halt(0);
        }
        byte[] semantic = DeviceWriter.signed(ROOT, identity, DeviceWriter.displayName("Linux device"), new byte[8], List.of());
        var object = V1EnvelopeWriter.seal(ROOT, semantic);
        System.out.println(object.id().filename()); System.out.flush();
        if (publisher.publishDurably(object.id(), object.bytes()) != V1ObjectPublicationStore.PublicationResult.PUBLISHED_NEW)
            throw new AssertionError("not new");
        Runtime.getRuntime().halt(0);
    }
}
