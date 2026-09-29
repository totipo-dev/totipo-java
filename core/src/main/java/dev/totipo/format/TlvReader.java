package dev.totipo.format;

/** Generic r16 framing only. Borrows the input synchronously; fields own copies. */
final class TlvReader {
    enum Status { FIELD, END, TRUNCATED_HEADER, TRUNCATED_VALUE }

    record Result(Status status, TlvField field) {}

    private final ByteCursor bytes;
    private Result terminal;

    TlvReader(byte[] input, int offset, int length) {
        bytes = new ByteCursor(input, offset, length);
    }

    Result next() {
        if (terminal != null) {
            return terminal;
        }
        if (bytes.remaining() == 0) {
            return finish(Status.END);
        }
        boolean headerComplete = false;
        try {
            bytes.require(4);
            int tag = bytes.u16be();
            int length = bytes.u16be();
            headerComplete = true;
            // The complete header was checked above. copy checks length against the
            // remaining slice BEFORE allocation; no offset+wireLength sum can overflow.
            // u16 length <=65535, so even 4+length is representable as an int.
            return new Result(Status.FIELD, new TlvField(tag, bytes.copy(length)));
        } catch (ByteCursor.TruncatedInput e) {
            return finish(headerComplete ? Status.TRUNCATED_VALUE : Status.TRUNCATED_HEADER);
        }
    }

    private Result finish(Status status) {
        // A failed field cannot be skipped by retrying and treating its value as a header.
        terminal = new Result(status, null);
        return terminal;
    }
}
