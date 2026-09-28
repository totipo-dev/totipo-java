package dev.totipo.format;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/** One-object Section 49 rename/reaffirmation against a selected accepted snapshot. */
final class DevicePresentationUpdate {
    private DevicePresentationUpdate() {}
    enum Status {
        PUBLISHED, DEVICE_IDENTITY_UNAVAILABLE, DEVICE_IDENTITY_BINDING_MISMATCH,
        NO_EXISTING_DEVICE, OPAQUE_DEVICE_HEAD, INVALID_DISPLAY_NAME, FOLD_REQUIRED,
        SIGNING_FAILED, LOCAL_VALIDATION_FAILED, PUBLICATION_INCOMPLETE
    }
    record Result(Status status, ObjectId objectId) {}
    private static Result failure(Status status) { return new Result(status, null); }

    static Result publish(byte[] root, SnapshotSession session, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store) {
        return publish(root, session, identity, name, authorTime, store, () -> {});
    }
    static Result publish(byte[] root, SnapshotSession session, DeviceIdentityResult identity,
                          String name, byte[] authorTime, V1ObjectPublicationStore store, Runnable beforePublication) {
        byte[] exactRoot = root.clone(), time = authorTime.clone();
        byte[] semantic = null;
        try {
            if (exactRoot.length != 32 || time.length != 8) { throw new IllegalArgumentException("Root/time width"); }
            var gate = InitialTokenPublication.gate(new InitialDeviceAdvertisement.Context(session), exactRoot, identity);
            if (gate != null) { return failure(gate == InitialTokenPublication.Status.DEVICE_IDENTITY_BINDING_MISMATCH
                    ? Status.DEVICE_IDENTITY_BINDING_MISMATCH : Status.DEVICE_IDENTITY_UNAVAILABLE); }
            var deviceId = new SecurityBytes(identity.deviceId(), 32);
            var snapshot = session.snapshot();
            var heads = snapshot.topology().currentDeviceHeads(deviceId);
            if (heads.isEmpty()) { return failure(Status.NO_EXISTING_DEVICE); }
            if (heads.stream().anyMatch(id -> ((AcceptedDevice) snapshot.object(id)).semanticStatus() == SemanticStatus.OPAQUE_ROUTABLE)) {
                return failure(Status.OPAQUE_DEVICE_HEAD);
            }
            byte[] display;
            try { display = DeviceWriter.displayName(name); }
            catch (IllegalArgumentException e) { return failure(Status.INVALID_DISPLAY_NAME); }
            try { DeviceWriter.requireCapacity(display.length, heads.size()); }
            catch (IllegalArgumentException e) { return failure(Status.FOLD_REQUIRED); }
            var parents = DeviceWriter.canonicalParents(heads);
            try { semantic = DeviceWriter.signed(exactRoot, identity, display, time, parents); }
            catch (GeneralSecurityException e) { return failure(Status.SIGNING_FAILED); }
            catch (IllegalStateException e) { return failure(Status.LOCAL_VALIDATION_FAILED); }
            var object = V1EnvelopeWriter.seal(exactRoot, semantic);
            var node = new AcceptedDevice(object.id(), 1, SemanticStatus.SUPPORTED_VALID, deviceId,
                    parents, new BigInteger(1, time), new SecurityBytes(identity.publicKeyX963(), 65), name, ProvenanceStatus.VERIFIED);
            beforePublication.run();
            try {
                if (store.publish(object.id(), object.bytes()) == null) { return failure(Status.PUBLICATION_INCOMPLETE); }
            } catch (IOException | RuntimeException e) { return failure(Status.PUBLICATION_INCOMPLETE); }
            session.accept(node);
            return new Result(Status.PUBLISHED, object.id());
        } finally {
            Arrays.fill(exactRoot, (byte) 0);
            if (semantic != null) { Arrays.fill(semantic, (byte) 0); }
        }
    }
}
