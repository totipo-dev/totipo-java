package dev.totipo.format;

/** Snapshot-derived relationship; never persisted inside a durable routing node. */
record ParentEdge(ObjectId childObjectId, ObjectId parentObjectId, ParentEdgeStatus status) {}
