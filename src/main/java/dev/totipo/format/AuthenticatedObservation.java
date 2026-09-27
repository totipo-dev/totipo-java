package dev.totipo.format;

import java.util.Optional;

/** Projection only. Neither decrypts, parses, validates assertions nor evaluates provenance. */
final class AuthenticatedObservation {
    private final DurableRecord record;

    private AuthenticatedObservation(DurableRecord record) { this.record = record; }

    static AuthenticatedObservation supported(AssertionValidator.AssertionValidObject assertion) {
        var value = assertion.plaintext();
        return scoped(assertion.objectId(), value.routing(), SemanticStatus.SUPPORTED_VALID,
                value.device() == null ? null : new SecurityBytes(value.device().publicKey(), 65));
    }

    /** Only EnvelopeReader can construct its result and bind the ID/source bytes to authentication. */
    static Optional<AuthenticatedObservation> opaque(EnvelopeReader.Result authenticated) {
        return switch (authenticated.status()) {
            case AUTHENTICATED_FUTURE_TOKEN, AUTHENTICATED_FUTURE_DEVICE ->
                Optional.of(scoped(authenticated.objectId(), authenticated.routing().prefix(),
                        SemanticStatus.OPAQUE_ROUTABLE, null));
            case AUTHENTICATED_OPAQUE_UNSCOPED -> Optional.of(new AuthenticatedObservation(
                    new OpaqueUnscopedRecord(authenticated.objectId(),
                            new SecurityBytes(authenticated.exactObjectBytes(), 1024))));
            default -> Optional.empty(); // Supported structure still requires M1 assertion validity.
        };
    }

    private static AuthenticatedObservation scoped(ObjectId id, RoutingPrefix prefix,
                                                   SemanticStatus status, SecurityBytes key) {
        var parents = prefix.parents().stream().map(ObjectId::new).toList();
        var identity = new SecurityBytes(prefix.identity(), 32);
        DurableRecord record = prefix.objectType() == 1
                ? new KnownTokenNode(id, prefix.version(), status, identity, parents,
                        new SecurityBytes(prefix.authorDeviceId(), 32), prefix.authorTime())
                : new KnownDeviceNode(id, prefix.version(), status, identity, parents, prefix.authorTime(), key);
        return new AuthenticatedObservation(record);
    }

    DurableRecord record() { return record; }
}

