package dev.totipo.format;

/** Cycle validity only; other causes of lost continuity remain on DurableKnowledgeState. */
enum GraphIntegrityStatus { ACYCLIC, RESOLVED_CYCLE }
