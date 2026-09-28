package dev.totipo.format;

import java.util.Optional;

/** Projection only. Neither decrypts, parses, validates assertions nor evaluates provenance. */
final class AuthenticatedObservation {
    private final AcceptedObject record;

    private AuthenticatedObservation(AcceptedObject record) { this.record = record; }

    static AuthenticatedObservation supported(AssertionValidator.AssertionValidObject assertion) {
        return supported(assertion, ProvenanceStatus.UNRESOLVED);
    }

    static AuthenticatedObservation supported(AssertionValidator.AssertionValidObject assertion, ProvenanceStatus provenance) {
        var value = assertion.plaintext();
        return scoped(assertion.objectId(), value.routing(), SemanticStatus.SUPPORTED_VALID,
                value.device() == null ? null : new SecurityBytes(value.device().publicKey(), 65),
                value.token() == null ? null : TokenValue.from(value.token()),
                value.device() == null ? null : value.device().displayName(), provenance);
    }

    /** Only EnvelopeReader can construct its result and bind the ID/source bytes to authentication. */
    static Optional<AuthenticatedObservation> opaque(EnvelopeReader.Result authenticated) {
        return switch (authenticated.status()) {
            case AUTHENTICATED_FUTURE_TOKEN, AUTHENTICATED_FUTURE_DEVICE ->
                Optional.of(scoped(authenticated.objectId(), authenticated.routing().prefix(),
                        SemanticStatus.OPAQUE_ROUTABLE, null, null, null, ProvenanceStatus.UNRESOLVED));
            case AUTHENTICATED_OPAQUE_UNSCOPED -> Optional.of(new AuthenticatedObservation(
                    new OpaqueUnscopedRecord(authenticated.objectId())));
            default -> Optional.empty(); // Supported structure still requires M1 assertion validity.
        };
    }

    private static AuthenticatedObservation scoped(ObjectId id, RoutingPrefix prefix,
                                                   SemanticStatus status, SecurityBytes key, TokenValue value,
                                                   String name, ProvenanceStatus provenance) {
        var parents = prefix.parents().stream().map(ObjectId::new).toList();
        var identity = new SecurityBytes(prefix.identity(), 32);
        AcceptedObject record = prefix.objectType() == 1
                ? new AcceptedToken(id, prefix.version(), status, identity, parents,
                        new SecurityBytes(prefix.authorDeviceId(), 32), prefix.authorTime(), value)
                : new AcceptedDevice(id, prefix.version(), status, identity, parents, prefix.authorTime(), key, name, provenance);
        return new AuthenticatedObservation(record);
    }

    AcceptedObject record() { return record; }
}
