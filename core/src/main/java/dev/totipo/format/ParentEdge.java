package dev.totipo.format;

/** Snapshot-derived relationship; derived only from current accepted objects. */
record ParentEdge(ObjectId childObjectId, ObjectId parentObjectId, ParentEdgeStatus status) {}
