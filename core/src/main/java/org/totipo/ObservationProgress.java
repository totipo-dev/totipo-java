package org.totipo;

public sealed interface ObservationProgress {
    record Enumerating(long discovered) implements ObservationProgress { }
    record Processing(long processed, long total) implements ObservationProgress { }
    record Finished(long processed, boolean hasDiagnostics) implements ObservationProgress { }
}

