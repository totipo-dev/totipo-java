package dev.totipo.format;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.List;
import java.util.function.Supplier;

/** Initial DEVICE publication against one selected snapshot. Thread-confined. */
final class InitialDeviceAdvertisement {
    private InitialDeviceAdvertisement() {}
    enum Status {
        PUBLISHED, DEVICE_IDENTITY_UNAVAILABLE, DEVICE_IDENTITY_BINDING_MISMATCH,
        DEVICE_FRONTIER_NOT_EMPTY, INVALID_DISPLAY_NAME, CAPACITY_EXCEEDED,
        SIGNING_FAILED, LOCAL_VALIDATION_FAILED, PUBLICATION_INCOMPLETE
    }
    record Context(SnapshotSession session) {}
    record Result(Status status, ObjectId objectId, SecurityBytes deviceId,
                  TokenPublicationSuccessGate.VerifiedDeviceAdvertisement receipt) {}
    private static Result failure(Status status) { return new Result(status, null, null, null); }
    static Result publish(byte[] root, Supplier<Context> current, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store) {
        return publish(root, current, identity, name, authorTime, store, () -> {});
    }
    static Result publish(byte[] root, Supplier<Context> current, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store, Runnable beforePublication) {
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        byte[] semantic = null;
        try {
            if (exactRoot.length != 32 || time.length != 8) { throw new IllegalArgumentException("Root/time width"); }
            var context = current.get();
            var gate = InitialTokenPublication.gate(context, exactRoot, identity);
            if (gate != null) { return failure(gate == InitialTokenPublication.Status.DEVICE_IDENTITY_BINDING_MISMATCH
                    ? Status.DEVICE_IDENTITY_BINDING_MISMATCH : Status.DEVICE_IDENTITY_UNAVAILABLE); }
            var deviceId = new SecurityBytes(identity.deviceId(), 32);
            if (!context.session().snapshot().topology().currentDeviceHeads(deviceId).isEmpty()) {
                return failure(Status.DEVICE_FRONTIER_NOT_EMPTY);
            }
            byte[] display;
            try { display = DeviceWriter.displayName(name); }
            catch (IllegalArgumentException e) { return failure(Status.INVALID_DISPLAY_NAME); }
            try { DeviceWriter.requireCapacity(display.length, 0); }
            catch (IllegalArgumentException e) { return failure(Status.CAPACITY_EXCEEDED); }
            try { semantic = DeviceWriter.signed(exactRoot, identity, display, time, List.of()); }
            catch (GeneralSecurityException e) { return failure(Status.SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            var object = V1EnvelopeWriter.seal(exactRoot, semantic);
            var node = new AcceptedDevice(object.id(), 1, SemanticStatus.SUPPORTED_VALID, deviceId,
                    List.of(), new BigInteger(1, time), new SecurityBytes(identity.publicKeyX963(), 65));
            beforePublication.run();
            try {
                if (store.publish(object.id(), object.bytes()) == null) { return failure(Status.PUBLICATION_INCOMPLETE); }
            } catch (IOException | RuntimeException e) { return failure(Status.PUBLICATION_INCOMPLETE); }
            context.session().accept(node);
            return new Result(Status.PUBLISHED, object.id(), deviceId,
                    TokenPublicationSuccessGate.acknowledged(node, context.session().binding()));
        } finally {
            Arrays.fill(exactRoot, (byte) 0);
            if (semantic != null) { Arrays.fill(semantic, (byte) 0); }
        }
    }
}
