package dev.totipo.format;

/** A framed field with owned value bytes; no family/schema meaning is implied. */
record TlvField(int tag, byte[] value) {
    TlvField {
        if (tag < 0 || tag > 0xffff) {
            throw new IllegalArgumentException("Tag outside u16 range");
        }
        value = value.clone();
    }

    @Override
    public byte[] value() {
        return value.clone();
    }

    int length() {
        return value.length;
    }
}
