package dev.totipo.format;

/** Local-only §10 lifecycle. No key material, reset or implicit binding replacement. */
record LocalEstablishment(Phase phase, SecurityBytes binding) {
    enum Phase { UNESTABLISHED, PENDING, ESTABLISHED }
    LocalEstablishment {
        if (phase == null || (phase == Phase.UNESTABLISHED ? binding != null
                : binding == null || binding.size() != 32)) {
            throw new IllegalArgumentException("Invalid establishment");
        }
    }
    static LocalEstablishment fresh() { return new LocalEstablishment(Phase.UNESTABLISHED, null); }
    LocalEstablishment transition(Phase target, SecurityBytes value) {
        var next = new LocalEstablishment(target, value);
        if (equals(next)) { return this; }
        if (target == Phase.UNESTABLISHED || phase == Phase.ESTABLISHED
                || phase == Phase.PENDING && (target != Phase.ESTABLISHED || !binding.equals(value))) {
            throw new IllegalArgumentException("Invalid establishment transition");
        }
        return next;
    }
    @Override public String toString() { return "LocalEstablishment[" + phase + "]"; }
}
