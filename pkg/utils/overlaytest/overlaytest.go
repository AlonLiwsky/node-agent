// Package overlaytest builds container-like fixtures on real overlayfs mounts
// for tests: several overlays that share one lower directory (as containers of
// one image share their image layers), each with a process whose root is that
// overlay (so /proc/<pid>/root and /proc/<pid>/mountinfo look like a container's).
// It needs root, a kernel with overlayfs and a Go toolchain, and skips otherwise.
package overlaytest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// helperSource is a static program that blocks until its stdin is closed. It is
// the only executable a chrooted process needs.
const helperSource = `package main

import (
	"io"
	"os"
)

func main() { _, _ = io.Copy(io.Discard, os.Stdin) }
`

// Container is one overlay mount plus the processes whose root is that mount.
type Container struct {
	// PID is a process whose root is the overlay, like a container's init process.
	PID uint32
	// Upper is the overlay's upper directory on the underlying filesystem.
	Upper string

	fixture *Fixture
	merged  string
}

// Root returns the path of the container's root as seen from the host,
// /proc/<pid>/root.
func (c *Container) Root() string { return procRoot(c.PID) }

// AddProcess starts one more process in the container, like another process of
// the same container, and returns its pid.
func (c *Container) AddProcess(tb testing.TB) uint32 {
	tb.Helper()
	return c.fixture.startProcess(tb, c.merged)
}

// Fixture holds the shared lower directory and the containers.
type Fixture struct {
	// Lower is the shared lower directory: the "image".
	Lower      string
	Containers []*Container
}

// New mounts n overlays that share one lower directory containing the given
// files (path relative to the root, content), and starts a process in each.
func New(tb testing.TB, n int, lowerFiles map[string][]byte) *Fixture {
	tb.Helper()
	if os.Geteuid() != 0 {
		tb.Skip("overlaytest: needs root to mount")
	}
	goBin := findGo()
	if goBin == "" {
		tb.Skip("overlaytest: needs the go toolchain to build the helper process")
	}

	// Overlay layers cannot live on overlayfs themselves, so use a tmpfs.
	base := tb.TempDir()
	if err := unix.Mount("tmpfs", base, "tmpfs", 0, ""); err != nil {
		tb.Skipf("overlaytest: cannot mount tmpfs: %v", err)
	}
	tb.Cleanup(func() { _ = unix.Unmount(base, unix.MNT_DETACH) })

	f := &Fixture{Lower: filepath.Join(base, "lower")}
	require.NoError(tb, os.MkdirAll(f.Lower, 0o755))
	for name, content := range lowerFiles {
		p := filepath.Join(f.Lower, name)
		require.NoError(tb, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(tb, os.WriteFile(p, content, 0o755))
	}
	buildHelper(tb, goBin, filepath.Join(f.Lower, "helper"))

	for i := 0; i < n; i++ {
		c := &Container{
			fixture: f,
			merged:  filepath.Join(base, "merged", string(rune('a'+i))),
			Upper:   filepath.Join(base, "upper", string(rune('a'+i))),
		}
		work := filepath.Join(base, "work", string(rune('a'+i)))
		for _, d := range []string{c.merged, c.Upper, work} {
			require.NoError(tb, os.MkdirAll(d, 0o755))
		}
		opts := "lowerdir=" + f.Lower + ",upperdir=" + c.Upper + ",workdir=" + work
		if err := unix.Mount("overlay", c.merged, "overlay", 0, opts); err != nil {
			tb.Skipf("overlaytest: cannot mount overlay: %v", err)
		}
		merged := c.merged
		tb.Cleanup(func() { _ = unix.Unmount(merged, unix.MNT_DETACH) })
		c.PID = f.startProcess(tb, c.merged)
		f.Containers = append(f.Containers, c)
	}
	return f
}

func (f *Fixture) startProcess(tb testing.TB, merged string) uint32 {
	tb.Helper()
	cmd := exec.Command("/helper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: merged}
	stdin, err := cmd.StdinPipe()
	require.NoError(tb, err)
	require.NoError(tb, cmd.Start())
	tb.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Wait()
	})
	return uint32(cmd.Process.Pid)
}

// findGo finds the go tool. Under sudo, PATH often lacks it, so it falls back to
// the toolchain that built this binary.
func findGo() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	p := filepath.Join(runtime.GOROOT(), "bin", "go")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func buildHelper(tb testing.TB, goBin, out string) {
	tb.Helper()
	src := tb.TempDir()
	require.NoError(tb, os.WriteFile(filepath.Join(src, "main.go"), []byte(helperSource), 0o644))
	require.NoError(tb, os.WriteFile(filepath.Join(src, "go.mod"), []byte("module helper\n\ngo 1.21\n"), 0o644))
	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("overlaytest: building helper: %v\n%s", err, b)
	}
}

func procRoot(pid uint32) string {
	return "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/root"
}
