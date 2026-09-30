package dev.totipo;

import java.time.Duration;
/** Fluent field editing shared by the three distinct builders. Builders are thread-confined. */
public interface TokenEditor<T extends TokenEditor<T>> extends AutoCloseable {
    T status(TokenStatus value);
    T issuer(String value);
    T account(String value);
    T algorithm(TotpAlgorithm value);
    T digits(int value);
    T period(Duration value);
    T secret(NewSecret value);
    T metadata(ClientMetadata value);
    /** May block for observation, local crypto and configured-store I/O. */
    SaveResult save();
    @Override void close();
}
