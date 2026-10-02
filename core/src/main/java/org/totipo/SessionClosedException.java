package org.totipo;

public final class SessionClosedException extends IllegalStateException {
    private static final long serialVersionUID = 1L;
    public SessionClosedException() { super("Vault session closed"); }
}

