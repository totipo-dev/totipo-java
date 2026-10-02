package org.totipo;

/** Partial publication cannot discover AdditionalConflict: its semantic basis is already frozen. */
public sealed interface PartialSaveResult extends SaveResult permits RetryResult, SaveResult.Failed { }
