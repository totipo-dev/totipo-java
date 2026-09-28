package dev.totipo.fs.linux;

/** Reviewed Linux x86-64 UAPI only: asm-generic/fcntl.h, errno-base.h, linux/fcntl.h, linux/stat.h. */
final class LinuxAbi {
    private LinuxAbi() {}
    static final int O_RDONLY = 0, O_NONBLOCK = 04000, O_DIRECTORY = 0200000,
            O_NOFOLLOW = 0400000, O_CLOEXEC = 02000000, O_PATH = 010000000;
    static final int AT_EMPTY_PATH = 0x1000, STATX_TYPE = 1, STATX_MODE = 2, STATX_INO = 0x100;
    static final int S_IFMT = 0170000, S_IFREG = 0100000, S_IFDIR = 0040000;
    static final int ENOENT = 2, EINTR = 4, EAGAIN = 11, ENOTDIR = 20, ELOOP = 40;
    static final int PIN = O_PATH | O_NOFOLLOW | O_CLOEXEC;
    static final int DIRECTORY = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC;
    // Installed Linux 7.2 UAPI asm-generic/fcntl.h and linux/fcntl.h (amd64).
    static final int O_RDWR = 2, O_TMPFILE = 020000000 | O_DIRECTORY;
    static final int AT_FDCWD = -100, AT_SYMLINK_FOLLOW = 0x400;
    static final int EEXIST = 17, EINVAL = 22, EOPNOTSUPP = 95;
    // Installed linux-headers-7.2/include/linux/fs.h: RENAME_EXCHANGE (1 << 1).
    static final int RENAME_EXCHANGE = 2;
}
