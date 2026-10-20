package ruleadapters

import (
	"bufio"
	"crypto/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/armosec/armoapi-go/armotypes"
	"github.com/goradd/maps"
	igtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/kubescape/node-agent/pkg/rulemanager/types"
	"github.com/kubescape/node-agent/pkg/utils/overlaytest"
)

type benchEvent struct {
	MockEnrichEvent
}

func (e *benchEvent) GetTimestamp() igtypes.Time { return igtypes.Time(time.Now().UnixNano()) }

// bytesRead returns the bytes this process has read through read(2), from
// /proc/self/io. It counts what the hashing reads, whatever the implementation.
func bytesRead(b *testing.B) uint64 {
	f, err := os.Open("/proc/self/io")
	if err != nil {
		b.Skipf("no /proc/self/io: %v", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "rchar: "); ok {
			n, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				b.Fatal(err)
			}
			return n
		}
	}
	b.Fatal("rchar not found in /proc/self/io")
	return 0
}

func benchAlert(c *RuleFailureCreator, pid uint32, containerID string) {
	rf := &types.GenericRuleFailure{}
	rf.SetRuntimeProcessDetails(armotypes.ProcessTree{ProcessTree: armotypes.Process{PID: pid, Path: "/bin"}})
	rf.SetTriggerEvent(&benchEvent{MockEnrichEvent{containerID: containerID}})
	c.setBaseRuntimeAlert(rf)
}

// BenchmarkAlertHashBurst measures a burst of alerts for one 8 MiB binary of one
// container, on a cold cache. The container is unknown to the creator, so each
// alert uses the pid of its own process, and every process has a different pid.
// Each op is one burst. It reports the bytes the burst read.
func BenchmarkAlertHashBurst(b *testing.B) {
	const (
		processes    = 8
		alertsPerPID = 8
	)
	content := make([]byte, 8<<20)
	if _, err := rand.Read(content); err != nil {
		b.Fatal(err)
	}
	fx := overlaytest.New(b, 1, map[string][]byte{"bin": content})
	var pids []uint32
	for k := 0; k < processes; k++ {
		pids = append(pids, fx.Containers[0].AddProcess(b))
	}
	// A file changed within the racy window is not cached; wait it out.
	time.Sleep(racyWindow + 500*time.Millisecond)

	before := bytesRead(b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := NewRuleFailureCreator(nil, nil, nil, armotypes.AlertSourcePlatformUnknown, "", new(maps.SafeMap[string, uint32]))
		for _, pid := range pids {
			for k := 0; k < alertsPerPID; k++ {
				benchAlert(c, pid, "unknown-container")
			}
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(bytesRead(b)-before)/float64(b.N)/(1<<20), "MiB-read/op")
}
