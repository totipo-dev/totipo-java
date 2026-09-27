package dev.totipo.fs.linux;

import java.io.IOException;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;

/** Linux UAPI struct statx: 256 bytes, alignment 8; native little endian on reviewed amd64. */
record LinuxStatx(int type, long inode, int deviceMajor, int deviceMinor) {
    static final int SIZE = 256, ALIGN = 8;
    static LinuxStatx decode(MemorySegment s) throws IOException {
        int required = LinuxAbi.STATX_TYPE | LinuxAbi.STATX_INO;
        if ((s.get(ValueLayout.JAVA_INT, 0) & required) != required) {
            throw new IOException("STATX_FIELDS_UNAVAILABLE");
        }
        return new LinuxStatx(s.get(ValueLayout.JAVA_SHORT, 28) & LinuxAbi.S_IFMT,
                s.get(ValueLayout.JAVA_LONG, 32), s.get(ValueLayout.JAVA_INT, 136),
                s.get(ValueLayout.JAVA_INT, 140));
    }
    boolean regular() { return type == LinuxAbi.S_IFREG; }
    void requireSame(LinuxStatx other) throws IOException {
        if (!equals(other)) { throw new IOException("FD_IDENTITY_MISMATCH"); }
    }
}
