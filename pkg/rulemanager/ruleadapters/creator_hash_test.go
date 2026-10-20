package ruleadapters

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils"
	"github.com/kubescape/node-agent/pkg/utils/overlaytest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// hashTestEvent is a trigger event that supplies only what setBaseRuntimeAlert reads.
type hashTestEvent struct {
	MockEnrichEvent
}

func (e *hashTestEvent) GetTimestamp() igtypes.Time { return igtypes.Time(1_700_000_000_000_000_000) }

// hashTestCreator is a RuleFailureCreator whose hash computation is counted.
type hashTestCreator struct {
	*RuleFailureCreator
	calls atomic.Int64
	delay time.Duration
}

func newHashTestCreator(containerPIDs map[string]uint32) *hashTestCreator {
	pids := new(maps.SafeMap[string, uint32])
	for id, pid := range containerPIDs {
		pids.Set(id, pid)
	}
	c := &hashTestCreator{RuleFailureCreator: NewRuleFailureCreator(nil, nil, nil, armotypes.AlertSourcePlatformUnknown, "", pids)}
	// Files in these tests are created a moment before they are hashed, so the
	// racy-clean rule is off unless a test turns it on.
	c.racyWindow = 0
	c.calculateHashes = func(r io.Reader) (string, string, error) {
		c.calls.Add(1)
		time.Sleep(c.delay)
		return utils.CalculateHashes(r)
	}
	return c
}

// alert runs setBaseRuntimeAlert for a process with the given pid and path in
// the given container, and returns the resulting base alert.
func (c *hashTestCreator) alert(pid uint32, path, containerID string, preset armotypes.BaseRuntimeAlert) armotypes.BaseRuntimeAlert {
	rf := &types.GenericRuleFailure{BaseRuntimeAlert: preset}
	rf.SetRuntimeProcessDetails(armotypes.ProcessTree{ProcessTree: armotypes.Process{PID: pid, Path: path}})
	rf.SetTriggerEvent(&hashTestEvent{MockEnrichEvent{containerID: containerID}})
	c.setBaseRuntimeAlert(rf)
	return rf.GetBaseRuntimeAlert()
}

// cacheableDir returns a temp dir whose files are cached. Files on tmpfs never
// are, so the tests that count hashes need a dir that is not on tmpfs.
func cacheableDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	var fs unix.Statfs_t
	require.NoError(t, unix.Statfs(dir, &fs))
	if fs.Type == unix.TMPFS_MAGIC {
		t.Skip("the temp dir is on tmpfs")
	}
	return dir
}

func hashesOf(content string) (sha1Hash, md5Hash string) {
	s := sha1.Sum([]byte(content))
	m := md5.Sum([]byte(content))
	return hex.EncodeToString(s[:]), hex.EncodeToString(m[:])
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o755))
}

func TestSetBaseRuntimeAlert_ConcurrentAlertsHashOnce(t *testing.T) {
	c := newHashTestCreator(nil)
	c.delay = 100 * time.Millisecond // keep the first hash running while the others arrive
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "some executable content")
	wantSHA1, wantMD5 := hashesOf("some executable content")

	const n = 32
	results := make([]armotypes.BaseRuntimeAlert, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), c.calls.Load(), "N concurrent alerts for one file must hash it once")
	for _, r := range results {
		assert.Equal(t, wantMD5, r.MD5Hash)
		assert.Equal(t, wantSHA1, r.SHA1Hash)
		assert.Equal(t, "23 B", r.Size)
	}
}

func TestSetBaseRuntimeAlert_ChangedFileIsRehashed(t *testing.T) {
	c := newHashTestCreator(nil)
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "version one")

	first := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	wantSHA1, wantMD5 := hashesOf("version one")
	assert.Equal(t, wantMD5, first.MD5Hash)
	assert.Equal(t, wantSHA1, first.SHA1Hash)
	again := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	assert.Equal(t, first, again)
	assert.Equal(t, int64(1), c.calls.Load(), "an unchanged file is served from the cache")

	t.Run("same size, new content", func(t *testing.T) {
		writeTestFile(t, path, "version two")
		require.NoError(t, os.Chtimes(path, time.Now(), time.Now().Add(-time.Hour)))
		got := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
		wantSHA1, wantMD5 := hashesOf("version two")
		assert.Equal(t, wantMD5, got.MD5Hash)
		assert.Equal(t, wantSHA1, got.SHA1Hash)
		assert.Equal(t, int64(2), c.calls.Load())
	})
	t.Run("different size", func(t *testing.T) {
		writeTestFile(t, path, "version three, longer")
		got := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
		wantSHA1, wantMD5 := hashesOf("version three, longer")
		assert.Equal(t, wantMD5, got.MD5Hash)
		assert.Equal(t, wantSHA1, got.SHA1Hash)
		assert.Equal(t, int64(3), c.calls.Load())
	})
}

func TestSetBaseRuntimeAlert_PresetFieldsAreKept(t *testing.T) {
	c := newHashTestCreator(nil)
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "content")

	got := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{MD5Hash: "m", SHA1Hash: "s", Size: "1 TB"})
	assert.Equal(t, "m", got.MD5Hash)
	assert.Equal(t, "s", got.SHA1Hash)
	assert.Equal(t, "1 TB", got.Size)
	assert.Zero(t, c.calls.Load())
}

func TestSetBaseRuntimeAlert_UnreadableFileGivesAlertWithoutHashes(t *testing.T) {
	c := newHashTestCreator(nil)
	dir := cacheableDir(t)

	t.Run("file does not exist", func(t *testing.T) {
		got := c.alert(uint32(os.Getpid()), filepath.Join(dir, "missing"), "c1", armotypes.BaseRuntimeAlert{})
		assert.Empty(t, got.MD5Hash)
		assert.Empty(t, got.SHA1Hash)
		assert.Empty(t, got.Size)
	})
	t.Run("directory keeps its size and has no hashes", func(t *testing.T) {
		got := c.alert(uint32(os.Getpid()), dir, "c1", armotypes.BaseRuntimeAlert{})
		assert.NotEmpty(t, got.Size)
		assert.Empty(t, got.MD5Hash)
		assert.Empty(t, got.SHA1Hash)
	})
	assert.Zero(t, c.calls.Load())
}

// A FIFO has no size and opening it for reading blocks until a writer appears.
// The alert must come back without opening it.
func TestSetBaseRuntimeAlert_FIFODoesNotBlock(t *testing.T) {
	c := newHashTestCreator(nil)
	fifo := filepath.Join(t.TempDir(), "fifo")
	require.NoError(t, unix.Mkfifo(fifo, 0o600))

	done := make(chan armotypes.BaseRuntimeAlert, 1)
	go func() { done <- c.alert(uint32(os.Getpid()), fifo, "c1", armotypes.BaseRuntimeAlert{}) }()
	select {
	case got := <-done:
		assert.Empty(t, got.MD5Hash)
		assert.Empty(t, got.SHA1Hash)
		assert.Empty(t, got.Size)
	case <-time.After(5 * time.Second):
		t.Fatal("setBaseRuntimeAlert blocked on a FIFO")
	}
	assert.Zero(t, c.calls.Load())
}

func TestSetBaseRuntimeAlert_TmpfsFilesAreNotCached(t *testing.T) {
	dir, err := os.MkdirTemp("/dev/shm", "hashtest")
	if err != nil {
		t.Skipf("no /dev/shm: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	c := newHashTestCreator(nil)
	path := filepath.Join(dir, "bin")
	writeTestFile(t, path, "tmpfs content")
	wantSHA1, wantMD5 := hashesOf("tmpfs content")

	for i := 0; i < 2; i++ {
		got := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
		assert.Equal(t, wantMD5, got.MD5Hash)
		assert.Equal(t, wantSHA1, got.SHA1Hash)
	}
	assert.Equal(t, int64(2), c.calls.Load(), "a file on tmpfs is hashed every time")
}

func TestSetBaseRuntimeAlert_FileChangedWhileHashingIsNotCached(t *testing.T) {
	c := newHashTestCreator(nil)
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "content one")
	hash := c.calculateHashes
	changed := false
	c.calculateHashes = func(r io.Reader) (string, string, error) {
		sha1Hash, md5Hash, err := hash(r)
		if !changed {
			changed = true
			writeTestFile(t, path, "content two")
			require.NoError(t, os.Chtimes(path, time.Now(), time.Now().Add(-time.Hour)))
		}
		return sha1Hash, md5Hash, err
	}

	got := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	assert.Empty(t, got.MD5Hash, "no hash is better than the hash of a file that moved under us")

	got = c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	wantSHA1, wantMD5 := hashesOf("content two")
	assert.Equal(t, wantMD5, got.MD5Hash)
	assert.Equal(t, wantSHA1, got.SHA1Hash)
}

func TestSetBaseRuntimeAlert_OnlyBytesOfTheIdentitySizeAreHashed(t *testing.T) {
	c := newHashTestCreator(nil)
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "0123456789")
	var read int64
	c.calculateHashes = func(r io.Reader) (string, string, error) {
		// The file grows after the stat but the reader must stop at the size.
		writeTestFile(t, path, "0123456789-and-more")
		n, err := io.Copy(io.Discard, r)
		read = n
		return "", "", err
	}
	c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	assert.Equal(t, int64(10), read)
}

func TestSetBaseRuntimeAlert_SameFileInTwoContainersIsHashedPerContainer(t *testing.T) {
	fx := overlaytest.New(t, 2, map[string][]byte{"bin": []byte("image binary")})
	a, b := fx.Containers[0], fx.Containers[1]
	c := newHashTestCreator(map[string]uint32{"container-a": a.PID, "container-b": b.PID})
	wantSHA1, wantMD5 := hashesOf("image binary")

	gotA := c.alert(0, "/bin", "container-a", armotypes.BaseRuntimeAlert{})
	assert.Equal(t, wantMD5, gotA.MD5Hash)
	assert.Equal(t, wantSHA1, gotA.SHA1Hash)
	assert.Equal(t, int64(1), c.calls.Load())
	assert.Equal(t, gotA, c.alert(0, "/bin", "container-a", armotypes.BaseRuntimeAlert{}), "same container: cache hit")
	assert.Equal(t, int64(1), c.calls.Load())

	gotB := c.alert(0, "/bin", "container-b", armotypes.BaseRuntimeAlert{})
	assert.Equal(t, gotA, gotB)
	assert.Equal(t, int64(2), c.calls.Load(), "another container does not share the entry")

	t.Run("processes of an unknown container reuse one hash", func(t *testing.T) {
		before := c.calls.Load()
		for i := 0; i < 5; i++ {
			pid := a.AddProcess(t) // each process has its own pid, and no container id maps to it
			got := c.alert(pid, "/bin", "unknown-container", armotypes.BaseRuntimeAlert{})
			assert.Equal(t, wantMD5, got.MD5Hash)
		}
		assert.Equal(t, before+1, c.calls.Load(), "a new pid must not mean a new hash")
	})
}

// On overlayfs a copied-up file keeps the inode number of the lower file, so two
// containers that copy the same lower file up and write different same-size
// content back to back hold different files with the same inode. Each overlay
// mount has its own st_dev, which keeps their keys apart. This checks the
// end result: each alert carries the hash of its own container's file.
func TestSetBaseRuntimeAlert_CopiedUpFilesInTwoContainersKeepTheirOwnHashes(t *testing.T) {
	fx := overlaytest.New(t, 2, map[string][]byte{"bin": []byte("image binary")})
	a, b := fx.Containers[0], fx.Containers[1]
	c := newHashTestCreator(map[string]uint32{"container-a": a.PID, "container-b": b.PID})
	imageSHA1, imageMD5 := hashesOf("image binary")

	// Prime the cache with the image file in both containers.
	for _, id := range []string{"container-a", "container-b"} {
		assert.Equal(t, imageMD5, c.alert(0, "/bin", id, armotypes.BaseRuntimeAlert{}).MD5Hash)
	}

	// Both containers write different content of the image file's size, back to back.
	require.NoError(t, os.WriteFile(filepath.Join(a.Root(), "bin"), []byte("AAAAAAAAAAAA"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(b.Root(), "bin"), []byte("BBBBBBBBBBBB"), 0o755))
	require.Len(t, "image binary", len("AAAAAAAAAAAA"))

	aSHA1, aMD5 := hashesOf("AAAAAAAAAAAA")
	bSHA1, bMD5 := hashesOf("BBBBBBBBBBBB")
	gotA := c.alert(0, "/bin", "container-a", armotypes.BaseRuntimeAlert{})
	gotB := c.alert(0, "/bin", "container-b", armotypes.BaseRuntimeAlert{})
	assert.Equal(t, aMD5, gotA.MD5Hash)
	assert.Equal(t, aSHA1, gotA.SHA1Hash)
	assert.Equal(t, bMD5, gotB.MD5Hash)
	assert.Equal(t, bSHA1, gotB.SHA1Hash)
	assert.NotEqual(t, imageSHA1, gotA.SHA1Hash)
}

// The kernel stamps mtime and ctime from a coarse clock. A same-size rewrite right
// after a change leaves (size, mtime, ctime) as they were, and no Chtimes is
// involved. With the racy-clean rule on, the second alert must see the new content.
func TestSetBaseRuntimeAlert_SameSizeRewriteRightAfterHashIsNotStale(t *testing.T) {
	c := newHashTestCreator(nil)
	c.racyWindow = racyWindow
	path := filepath.Join(cacheableDir(t), "bin")
	writeTestFile(t, path, "version one")

	first := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	wantSHA1, wantMD5 := hashesOf("version one")
	assert.Equal(t, wantMD5, first.MD5Hash)
	assert.Equal(t, wantSHA1, first.SHA1Hash)

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = f.WriteAt([]byte("version two"), 0)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	second := c.alert(uint32(os.Getpid()), path, "c1", armotypes.BaseRuntimeAlert{})
	wantSHA1, wantMD5 = hashesOf("version two")
	assert.Equal(t, wantMD5, second.MD5Hash)
	assert.Equal(t, wantSHA1, second.SHA1Hash)
}
