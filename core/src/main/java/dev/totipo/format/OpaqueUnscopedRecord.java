package dev.totipo.format;

record OpaqueUnscopedRecord(ObjectId objectId) implements AcceptedObject {
    OpaqueUnscopedRecord { java.util.Objects.requireNonNull(objectId); }
}
