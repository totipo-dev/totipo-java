package org.totipo.spi;

/** Coarse storage failures; provider exception details carry no protocol meaning. */
public enum StoreFailure { UNAVAILABLE, UNSAFE_NAMESPACE, UNSUPPORTED }
