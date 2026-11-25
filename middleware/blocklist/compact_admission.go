package blocklist

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"runtime"

	"github.com/semihalev/sdns/internal/compactset"
)

const compactDeviceReserve = 32 << 20
const compactRollingLinuxAdmission = runtime.GOOS == "linux"

var compactAvailableMemory func() (uint64, error)

const compactStreamMemory = 1 << 20      // HTTP copy / hosts scanner, fields and buffers
const compactManifestAllowance = 1 << 20 // existing manifest size limit

type compactAdmissionDisk struct{ available, capacity, block uint64 }

type compactAdmissionObserver struct {
	memory func() (uint64, error)
	disk   func(string) (compactAdmissionDisk, error)
}

func (c *compactManager) admissionError(resource, stage string, err error) error {
	active, durable := c.compactPolicyAges()
	return fmt.Errorf("compact replacement rejected: %s during %s: %w (active_policy_age=%s, last_durable_policy_age=%s)", resource, stage, err, active, durable)
}

func (c *compactManager) availableCompactMemory() (uint64, error) {
	if c.admissionObserver.memory != nil {
		return c.admissionObserver.memory()
	}
	return compactAvailableMemory()
}

// Delayed allocation can exclude recently written scratch from the free-block sample.
func (c *compactManager) admissionDisk(stage string) (budget, block uint64, err error) {
	var d compactAdmissionDisk
	if observe := c.admissionObserver.disk; observe != nil {
		d, err = observe(stage)
	} else {
		d, err = compactPolicyDisk(c.dir)
	}
	if err == nil && (d.block == 0 || d.capacity == 0 || d.available > d.capacity) {
		err = fmt.Errorf("invalid usable-block observation")
	}
	if err == nil {
		reserve := max(uint64(compactDeviceReserve), (d.capacity-1)/10+1)
		if d.available >= reserve {
			return d.available - reserve, d.block, nil
		}
		err = fmt.Errorf("%d usable free bytes below %d reserve", d.available, reserve)
	}
	return 0, 0, c.admissionError("flash", stage, err)
}

const compactCheckpointManifestStage = "checkpoint manifest"

func (c *compactManager) admitCheckpointManifest(bytes uint64) error {
	budget, block, err := c.admissionDisk(compactCheckpointManifestStage)
	if err != nil {
		return err
	}
	if need := compactBlockRound(bytes, block); need > budget {
		return c.admissionError("flash", compactCheckpointManifestStage, fmt.Errorf("need %d additional bytes; %d above reserve", need, budget))
	}
	return nil
}

func (c *compactManager) refreshDiskBudget(stage string) (uint64, uint64, error) {
	budget, block, err := c.admissionDisk(stage)
	if err != nil {
		return 0, 0, err
	}
	manifest := compactBlockRound(compactManifestAllowance, block)
	if budget < manifest {
		return 0, 0, c.admissionError("flash", stage, fmt.Errorf("need %d bytes for a concurrent checkpoint; %d above reserve", manifest, budget))
	}
	return budget - manifest, block, nil
}

func compactSizeAdd(a, b uint64) uint64 {
	n, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return ^uint64(0)
	}
	return n
}

func compactSizeMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}

func compactBlockRound(n, block uint64) uint64 {
	if n == 0 {
		return 0
	}
	return compactSizeMul(1+(n-1)/block, block)
}

const (
	rollingInstallWorkspace      = 16 << 20
	rollingRefreshWorkspace      = 24 << 20
	rollingRefreshStoreWorkspace = 16 << 20
	rollingRefreshChurnLimit     = 480_000
)

var errRollingRAM = errors.New("rolling memory admission")
var errRollingChurn = errors.New("rolling delta change limit")

// Opening an existing policy is not a replacement. Its startup scratch and
// sparse index must fit, but the startup sample already charges the running
// process, and clean mapped verification pages can be reclaimed as it goes.
func rollingOpenMemory(m *compactset.RollingManifest) uint64 {
	names, retained := m.RecordCounts()
	return compactSizeAdd(2<<20+m.CountVerificationScratch(), compactSizeAdd(names, retained))
}

// Replacement workspace and cold-open reserve are alternative peaks. Both
// must fit, but clean mapped pages can be reclaimed between stages.
func rollingColdReserve(names, retained uint64) uint64 {
	return compactSizeAdd(8<<20, compactSizeAdd(compactSizeMul(names, 4), compactSizeMul(retained, 8)))
}

func rollingRefreshMemory(names, changes uint64) uint64 {
	return compactSizeAdd(rollingRefreshWorkspace, compactSizeAdd(compactSizeMul(names, 8), compactSizeMul(changes, 90)))
}

func (c *compactManager) checkRollingMemory(stage string, available, working, reserve uint64) error {
	if available < max(working, reserve) {
		if reserve == 0 {
			return c.rollingRAMError(stage, fmt.Errorf("%d available bytes; need %d working bytes", available, working))
		}
		return c.rollingRAMError(stage, fmt.Errorf("%d available bytes; need %d working bytes or %d cold-reopen bytes, whichever is greater", available, working, reserve))
	}
	return nil
}

func (c *compactManager) rollingRAMError(stage string, err error) error {
	return c.admissionError("RAM", "rolling feed "+stage, fmt.Errorf("%w: %w", errRollingRAM, err))
}

func (c *compactManager) checkRollingReplacement(stage string, available, working, names, retained uint64) error {
	if !compactRollingLinuxAdmission {
		return nil
	}
	return c.checkRollingMemory(stage, available, working, max(compactDeviceReserve, rollingColdReserve(names, retained)))
}

// HTTP bodies may have no known length. Charge normalized input per buffered write.
type rollingInstallInput struct {
	manager   *compactManager
	available uint64
	bytes     uint64
	names     uint64
}

func (i *rollingInstallInput) wrap(out io.Writer) io.Writer {
	if !compactRollingLinuxAdmission {
		return out
	}
	return rollingInstallWriter{i, out}
}

type rollingInstallWriter struct {
	*rollingInstallInput
	out io.Writer
}

func (w rollingInstallWriter) Write(p []byte) (int, error) {
	w.bytes = compactSizeAdd(w.bytes, uint64(len(p)))
	w.names = compactSizeAdd(w.names, uint64(bytes.Count(p, []byte{'\n'}))) //nolint:gosec // bytes.Count is nonnegative
	working := rollingInstallMemory(w.names, w.bytes)
	if err := w.manager.checkRollingReplacement("install input", w.available, working, w.names, 0); err != nil {
		return 0, err
	}
	return w.out.Write(p)
}

func rollingInstallMemory(names, bytes uint64) uint64 {
	return compactSizeAdd(rollingInstallWorkspace, max(compactSizeMul(4, names), bytes/8))
}

var errCompactFeedWorking = errors.New("compact feed exceeds transient working memory")

const compactFeedWorkingLimit = 48 << 20 // used until a memory sample is needed

type compactFeedLedger struct{ used, limit int }

func (l *compactFeedLedger) reserve(n int) error {
	if n < 0 || n > l.limit-l.used {
		return errCompactFeedWorking
	}
	l.used += n
	return nil
}

const compactFeedKeyOverhead = 192

func compactFeedKeyCost(key string) int { return len(key) + compactFeedKeyOverhead }

type rollingAdmissionMode uint8

const (
	admitInstall rollingAdmissionMode = iota
	admitRestart
	admitRefresh
)

func (c *compactManager) admitRolling(mode rollingAdmissionMode, stage string) (available, workspace uint64, err error) {
	if !compactRollingLinuxAdmission {
		return math.MaxUint64, 1 << 30, nil
	}
	available, err = c.availableCompactMemory()
	if err != nil {
		return 0, compactFeedWorkingLimit, c.rollingRAMError(stage, err)
	}
	headroom := int64(min(available, math.MaxInt64)) - compactDeviceReserve
	workspace = uint64(max(rollingRefreshStoreWorkspace, min(headroom/2, 1<<30)))
	switch mode {
	case admitInstall:
		return available, workspace, c.checkRollingReplacement(stage, available, rollingInstallWorkspace, 0, 0)
	case admitRestart:
		return available, workspace, c.checkRollingMemory(stage, available, rollingOpenMemory(c.manifest.Rolling), 0)
	}
	names, retained := c.manifest.Rolling.RecordCounts()
	working := rollingRefreshMemory(names, 0)
	if err := c.checkRollingReplacement(stage, available, working, names, retained); err != nil {
		return available, workspace, err
	}
	overhead := working - rollingRefreshStoreWorkspace
	return available, min(workspace, available-overhead), nil
}

func (c *compactManager) rollingWriteAdmission(stage string) (func(uint64, uint64) error, error) {
	stage = "rolling feed " + stage
	budget, block, err := c.refreshDiskBudget(stage)
	if err != nil {
		return nil, err
	}
	return func(oldSize, newSize uint64) error {
		need := compactBlockRound(newSize, block) - compactBlockRound(oldSize, block)
		if need > budget {
			return c.admissionError("flash", stage, fmt.Errorf("need %d additional bytes; %d remaining above reserve", need, budget))
		}
		budget -= need
		return nil
	}, nil
}

func rollingLedger(workspace uint64) *compactFeedLedger {
	return &compactFeedLedger{used: compactStreamMemory + compactManifestAllowance, limit: int(workspace)} //nolint:gosec // the sampled limit is capped at 1 GiB
}
