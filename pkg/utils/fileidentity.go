package utils

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// ErrNotRegularFile is returned by OpenRegularFile for anything but a regular file.
var ErrNotRegularFile = errors.New("not a regular file")

// FileIdentity identifies the state of a file: a file that is still in the same
// state has the same identity. The kernel sets the inode number and ctime, and
// a user cannot set ctime.
//
// The identity is only as fine as the kernel's timestamps: a same-size rewrite
// within one tick of the clock that stamped the previous change leaves it
// unchanged, so a caller that caches by identity should not trust a file whose
// ctime is very recent.
type FileIdentity struct {
	Dev     uint64
	Ino     uint64
	Size    int64
	MtimeNs int64
	CtimeNs int64
}

func identityOf(st *unix.Stat_t) FileIdentity {
	return FileIdentity{
		Dev:     st.Dev,
		Ino:     st.Ino,
		Size:    st.Size,
		MtimeNs: st.Mtim.Nano(),
		CtimeNs: st.Ctim.Nano(),
	}
}

// StatFile returns the identity of the file at path, following symlinks, and
// whether it is a regular file. It never opens the file.
func StatFile(path string) (id FileIdentity, regular bool, err error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return FileIdentity{}, false, err
	}
	return identityOf(&st), st.Mode&unix.S_IFMT == unix.S_IFREG, nil
}

// OpenRegularFile opens the file at path for reading and returns it with its
// identity, read from the open descriptor. It never blocks on a special file:
// the file is opened with O_NONBLOCK (a FIFO would otherwise block the open until
// a writer appears) and rejected with ErrNotRegularFile unless the descriptor is
// a regular file. The check is on the descriptor, so a file replaced between a
// caller's StatFile and this call is still caught.
func OpenRegularFile(path string) (*os.File, FileIdentity, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, FileIdentity{}, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &st); err != nil {
		_ = file.Close()
		return nil, FileIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = file.Close()
		return nil, FileIdentity{}, ErrNotRegularFile
	}
	return file, identityOf(&st), nil
}

// IdentityOf returns the current identity of the open file f.
func IdentityOf(f *os.File) (FileIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return FileIdentity{}, err
	}
	return identityOf(&st), nil
}

// IsCacheableFS reports whether a FileIdentity of a file on f's filesystem
// reliably changes when the file's content changes. It does not on tmpfs: a write
// through a shared mmap changes the content without moving mtime or ctime. It
// also reports false when the filesystem cannot be read.
func IsCacheableFS(f *os.File) bool {
	var fs unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &fs); err != nil {
		return false
	}
	return fs.Type != unix.TMPFS_MAGIC
}
