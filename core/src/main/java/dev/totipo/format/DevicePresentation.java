package dev.totipo.format;

import java.util.Set;
import java.util.HashSet;

/** Section 31 authenticated current names, independent of DEVICE causality and TOKEN values. */
record DevicePresentation(State state, Set<String> names, Set<ObjectId> inertHeads) {
    enum State { NONE, VERIFIED, CONFLICTED, OPAQUE }
    DevicePresentation {
        names = Set.copyOf(names);
        inertHeads = Set.copyOf(inertHeads);
    }
    static DevicePresentation evaluate(AcceptedSnapshot snapshot, SecurityBytes deviceId) {
        var names = new HashSet<String>();
        var inert = new HashSet<ObjectId>();
        boolean opaque = false;
        for (var id : snapshot.topology().currentDeviceHeads(deviceId)) {
            var device = (AcceptedDevice) snapshot.object(id);
            if (device.semanticStatus() == SemanticStatus.OPAQUE_ROUTABLE) { opaque = true; }
            else if (device.provenance() == ProvenanceStatus.VERIFIED) { names.add(device.displayName()); }
            else { inert.add(id); }
        }
        // Do not offer a readable name as confidently current alongside opaque evidence.
        return new DevicePresentation(opaque ? State.OPAQUE : names.isEmpty() ? State.NONE
                : names.size() == 1 ? State.VERIFIED : State.CONFLICTED, opaque ? Set.of() : names, inert);
    }
    @Override public String toString() {
        return "DevicePresentation[state=" + state + ", names=" + names.size() + ", inertHeads=" + inertHeads.size() + "]";
    }
}
