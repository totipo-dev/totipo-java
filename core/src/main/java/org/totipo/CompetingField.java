package org.totipo;

import java.util.List;
import java.util.Objects;
public record CompetingField<T>(List<Value<T>> values) {
    public CompetingField { values = List.copyOf(values); }
    public boolean disagrees() { return values.size() > 1; }
    public record Value<T>(T value, List<TokenAlternative> alternatives) {
        public Value { Objects.requireNonNull(value); alternatives = List.copyOf(alternatives); }
    }
}

