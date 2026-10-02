package org.totipo;

import java.util.List;
public record CompetingSecret(List<SecretGroup> groups) {
    public CompetingSecret { groups = List.copyOf(groups); }
    public boolean disagrees() { return groups.size() > 1; }
}

