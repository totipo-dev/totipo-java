package dev.totipo;

import java.time.Duration;
import java.util.Objects;
public record TokenCompetition(CompetingField<TokenStatus> status, CompetingField<String> issuer,
    CompetingField<String> account, CompetingField<TotpAlgorithm> algorithm,
    CompetingField<Integer> digits, CompetingField<Duration> period, CompetingSecret secret) {
    public TokenCompetition {
        Objects.requireNonNull(status); Objects.requireNonNull(issuer); Objects.requireNonNull(account);
        Objects.requireNonNull(algorithm); Objects.requireNonNull(digits); Objects.requireNonNull(period);
        Objects.requireNonNull(secret);
    }
}
