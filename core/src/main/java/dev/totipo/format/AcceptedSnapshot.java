package dev.totipo.format;

import java.util.HashMap;
import java.util.Map;

/** Immutable process-local current evidence. Rebuild after each discovery pass. */
final class AcceptedSnapshot {
    private final Map<ObjectId, AcceptedObject> objects;
    private final boolean incomplete, conflictingEvidence;
    AcceptedSnapshot(Map<ObjectId, AcceptedObject> objects, boolean incomplete) {
        this(objects, incomplete, false);
    }
    private AcceptedSnapshot(Map<ObjectId, AcceptedObject> objects, boolean incomplete, boolean conflictingEvidence) {
        this.conflictingEvidence = conflictingEvidence;
        this.objects = Map.copyOf(objects);
        this.incomplete = incomplete;
        this.objects.forEach((id, object) -> {
            if (!id.equals(object.objectId())) { throw new IllegalArgumentException("Inconsistent object index"); }
        });
    }
    static AcceptedSnapshot empty() { return new AcceptedSnapshot(Map.of(), false); }
    Map<ObjectId, AcceptedObject> objects() { return objects; }
    AcceptedObject object(ObjectId id) { return objects.get(id); }
    boolean conflictingEvidence() { return conflictingEvidence; }
    boolean incomplete() { return incomplete; }
    boolean hasUnscopedEvidence() { return objects.values().stream().anyMatch(OpaqueUnscopedRecord.class::isInstance); }
    AcceptedSnapshot accepting(AcceptedObject object) {
        var next = new HashMap<>(objects);
        var old = next.putIfAbsent(object.objectId(), object);
        boolean conflict = old != null && !AcceptedObject.sameEvidence(old, object);
        if (old != null && !conflict) { next.put(object.objectId(), object); }
        return new AcceptedSnapshot(next, incomplete, conflictingEvidence || conflict);
    }
    GraphTopology topology() { return new GraphTopology(this); }
    VerificationKeyMaterial verificationKeys() {
        return VerificationKeyMaterial.available(objects.values().stream()
                .filter(AcceptedDevice.class::isInstance).map(AcceptedDevice.class::cast)
                .filter(d -> d.publicKeyX963() != null)
                .map(d -> new VerificationKeyMaterial.Candidate(d.deviceId().bytes(), d.publicKeyX963().bytes())).toList());
    }
    @Override public String toString() { return "AcceptedSnapshot[objects=" + objects.size() + ", incomplete=" + incomplete + "]"; }
}
