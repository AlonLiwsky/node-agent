package utils

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o755))
}

func TestOpenRegularFile_IdentityFollowsFileState(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bin")
	writeFile(t, p, "hello")

	f, id, err := OpenRegularFile(p)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	st, err := os.Stat(p)
	require.NoError(t, err)
	assert.Equal(t, int64(5), id.Size)
	assert.Equal(t, st.ModTime().UnixNano(), id.MtimeNs)

	statID, regular, err := StatFile(p)
	require.NoError(t, err)
	assert.True(t, regular)
	assert.Equal(t, id, statID, "the path stat and the descriptor agree")
	cur, err := IdentityOf(f)
	require.NoError(t, err)
	assert.Equal(t, id, cur)

	// Same size, new mtime (and so new ctime): a different identity.
	require.NoError(t, os.Chtimes(p, time.Now(), time.Now().Add(-time.Hour)))
	cur, err = IdentityOf(f)
	require.NoError(t, err)
	assert.NotEqual(t, id, cur)
}

// A FIFO must not block the open. Without O_NONBLOCK, opening a FIFO for reading
// blocks until a writer appears, so this test would time out.
func TestOpenRegularFile_FIFODoesNotBlock(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	done := make(chan error, 1)
	go func() {
		f, _, err := OpenRegularFile(fifo)
		if f != nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		assert.ErrorIs(t, err, ErrNotRegularFile)
	case <-time.After(5 * time.Second):
		t.Fatal("OpenRegularFile blocked on a FIFO")
	}

	_, regular, err := StatFile(fifo)
	require.NoError(t, err)
	assert.False(t, regular)
}

func TestOpenRegularFile_RejectsOtherTypes(t *testing.T) {
	_, _, err := OpenRegularFile(t.TempDir())
	assert.ErrorIs(t, err, ErrNotRegularFile)
	_, _, err = OpenRegularFile("/dev/null")
	assert.ErrorIs(t, err, ErrNotRegularFile)
	_, _, err = OpenRegularFile(filepath.Join(t.TempDir(), "missing"))
	assert.Error(t, err)
}

func TestIdentityOf_ClosedFileFails(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bin")
	writeFile(t, p, "hello")
	f, _, err := OpenRegularFile(p)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	_, err = IdentityOf(f)
	assert.Error(t, err)
}

func isTmpfs(t *testing.T, dir string) bool {
	t.Helper()
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs(dir, &fs))
	return fs.Type == unix.TMPFS_MAGIC
}

func TestIsCacheableFS(t *testing.T) {
	t.Run("tmpfs is not cacheable", func(t *testing.T) {
		dir, err := os.MkdirTemp("/dev/shm", "identity")
		if err != nil {
			t.Skipf("no /dev/shm: %v", err)
		}
		defer func() { _ = os.RemoveAll(dir) }()
		require.True(t, isTmpfs(t, dir), "/dev/shm is expected to be tmpfs")
		p := filepath.Join(dir, "bin")
		writeFile(t, p, "hello")
		f, _, err := OpenRegularFile(p)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		assert.False(t, IsCacheableFS(f))
	})
	t.Run("a disk or overlay filesystem is cacheable", func(t *testing.T) {
		dir := t.TempDir()
		if isTmpfs(t, dir) {
			t.Skip("the temp dir is on tmpfs")
		}
		p := filepath.Join(dir, "bin")
		writeFile(t, p, "hello")
		f, _, err := OpenRegularFile(p)
		require.NoError(t, err)
		defer func() { _ = f.Close() }()
		assert.True(t, IsCacheableFS(f))
	})
}
