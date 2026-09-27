package dev.totipo.format;

/** Ephemeral complete value evidence; only the M1 assertion boundary can supply it. */
final class ReadableTokenValue {
    private final KnownTokenNode routing;
    private final TokenValue value;

    private ReadableTokenValue(KnownTokenNode routing, TokenValue value) {
        this.routing = routing;
        this.value = value;
    }

    static ReadableTokenValue supported(AssertionValidator.AssertionValidObject assertion) {
        if (assertion.plaintext().token() == null) {
            throw new IllegalArgumentException("Requires supported TOKEN assertion");
        }
        return new ReadableTokenValue((KnownTokenNode) AuthenticatedObservation.supported(assertion).record(),
                TokenValue.from(assertion.plaintext().token()));
    }

    ObjectId objectId() { return routing.objectId(); }
    SecurityBytes tokenId() { return routing.tokenId(); }
    KnownTokenNode routing() { return routing; }
    TokenValue value() { return value; }
    @Override public String toString() { return "ReadableTokenValue[redacted]"; }
}
