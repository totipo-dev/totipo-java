package dev.totipo;

/** An already uncertain operation can only become Saved or remain PublicationUncertain. */
public sealed interface RetryResult extends PartialSaveResult
        permits SaveResult.Saved, SaveResult.PublicationUncertain { }
