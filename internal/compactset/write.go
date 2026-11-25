package compactset

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"syscall"
	"unsafe"

	"github.com/cespare/xxhash/v2"
)

type rollingLayout struct {
	id    uint16
	count uint32
	size  uint64
}

type rollingMeasure struct {
	layout rollingLayout
	prev   []byte
}

func (m *rollingMeasure) reset(id uint16) {
	m.layout = rollingLayout{id: id, size: 4}
	m.prev = m.prev[:0]
}

func (m *rollingMeasure) add(key []byte) error {
	p := &m.layout
	if p.count == math.MaxUint32 {
		return errRolling
	}
	prefix := psnRecordPrefix(m.prev, key, p.count)
	suffix := len(key) - prefix
	p.size += uint64(psnVarintSize(prefix) + psnVarintSize(suffix) + suffix) //nolint:gosec // G115: sum of header and suffix lengths.
	if p.count%psnBlock == 0 {
		p.size += 4
	}
	if p.size > psnMaxShardLength {
		return errRolling
	}
	m.prev = append(m.prev[:0], key...)
	p.count++
	return nil
}

func rollingLayouts(read func(func([]byte, uint64) error) error) ([]rollingLayout, int, error) {
	var out []rollingLayout
	var layout rollingMeasure
	var n int
	err := read(func(key []byte, _ uint64) error {
		id := psnID(key)
		if layout.layout.count == 0 || id != layout.layout.id {
			if layout.layout.count != 0 {
				out = append(out, layout.layout)
			}
			layout.reset(id)
		}
		if n == math.MaxInt {
			return errRolling
		}
		n++
		return layout.add(key)
	})
	if layout.layout.count != 0 {
		out = append(out, layout.layout)
	}
	return out, n, err
}

// rollingOutput uses an explicit origin so the same shard encoding works
// in standalone shards and embedded segment runs.
type rollingOutput struct {
	keys                     psnWriter
	masks                    *bufio.Writer
	keyHash                  xxhash.Digest
	hashKeys                 bool
	mask                     [8]byte
	width                    int
	offsets, records, owners io.OffsetWriter
}

func (w *rollingOutput) start(keys, masks *os.File, keyStart, maskStart int64, p rollingLayout, digest bool) {
	if w.keys.offsets == nil {
		w.keys.offsets = bufio.NewWriterSize(io.Discard, 16<<10)
		w.keys.records = bufio.NewWriterSize(io.Discard, 64<<10)
		w.masks = bufio.NewWriterSize(io.Discard, 16<<10)
	}
	w.keys.count, w.keys.prev = 0, w.keys.prev[:0]
	w.keys.pos = 4 + uint64(psnBlockCount(p.count))*4 //nolint:gosec // G115: unsigned count yields a nonnegative block count.
	w.offsets = *io.NewOffsetWriter(keys, keyStart)
	w.records = *io.NewOffsetWriter(keys, keyStart+int64(w.keys.pos)) //nolint:gosec // G115: the shard size is below 4 GiB.
	w.owners = *io.NewOffsetWriter(masks, maskStart)
	w.keys.offsets.Reset(&w.offsets)
	w.keys.records.Reset(&w.records)
	w.masks.Reset(&w.owners)
	var header [4]byte
	le.PutUint32(header[:], p.count)
	_, _ = w.keys.offsets.Write(header[:])
	w.hashKeys = digest
	if digest {
		w.keyHash.Reset()
	}
}

func (w *rollingOutput) add(key []byte, mask uint64) error {
	if err := w.keys.add(key); err != nil {
		return err
	}
	if w.hashKeys {
		_, _ = w.keyHash.Write(key)
		_, _ = w.keyHash.Write(psnNewline[:])
	}
	le.PutUint64(w.mask[:], mask)
	_, err := w.masks.Write(w.mask[:w.width])
	return err
}

func (w *rollingOutput) flush(p rollingLayout) error {
	if w.keys.count != p.count || w.keys.pos != p.size {
		return errRolling
	}
	return errors.Join(w.keys.offsets.Flush(), w.keys.records.Flush(), w.masks.Flush())
}

type rollingBaseWriter struct {
	files       *rollingFiles
	output      rollingOutput
	part, mask  *os.File
	meta        rollingPartMeta
	layout      rollingLayout
	hashBuf     []byte
	partHash    xxhash.Digest
	sidecarHash xxhash.Digest
}

func (w *rollingBaseWriter) start(p rollingLayout) (err error) {
	w.layout = p
	w.meta = rollingPartMeta{id: p.id, count: p.count, nonce: rollingNonce()}
	part, mask := w.meta.names()
	w.part, err = w.files.create(part, p.size)
	if err != nil {
		return err
	}
	w.mask, err = w.files.create(mask, uint64(p.count)*uint64(w.output.width)) //nolint:gosec // G115: mask width is 1, 2, 4, or 8.
	if err != nil {
		return err
	}
	w.output.start(w.part, w.mask, 0, 0, p, true)
	w.sidecarHash.Reset()
	w.output.masks.Reset(w)
	return nil
}

// Write streams each buffer of standalone sidecar bytes to disk and its digest.
func (w *rollingBaseWriter) Write(p []byte) (int, error) {
	n, err := w.mask.Write(p)
	_, _ = w.sidecarHash.Write(p[:n])
	return n, err
}

func (w *rollingBaseWriter) close() (err error) {
	if w.part != nil {
		err = w.part.Close()
		w.part = nil
	}
	if w.mask != nil {
		err = errors.Join(err, w.mask.Close())
		w.mask = nil
	}
	return err
}

func (w *rollingBaseWriter) finish(ctx context.Context) (p rollingPartMeta, err error) {
	if err = w.output.flush(w.layout); err != nil {
		return p, err
	}
	if w.hashBuf == nil {
		w.hashBuf = make([]byte, 32<<10)
	}
	p = w.meta
	p.keyDigest = w.output.keyHash.Sum64()
	p.sidecarDigest = w.sidecarHash.Sum64()
	w.partHash.Reset()
	// The offset writers have not changed the descriptor's read position.
	_, err = io.CopyBuffer(&w.partHash, rollingContextReader{ctx, w.part}, w.hashBuf)
	p.partitionDigest = w.partHash.Sum64()
	return p, errors.Join(err, w.close())
}

func (f *rollingFiles) catalog(start, end uint32, entries []rollingPartMeta) (ref rollingFile, err error) {
	name := fmt.Sprintf(rollingCatalogPrefix+"%x"+rollingBinarySuffix, rollingNonce())
	size := uint64(rollingCatalogHeader) + uint64(len(entries))*rollingCatalogEntryBytes
	file, err := f.create(name, size)
	if err != nil {
		return ref, err
	}
	defer func() { err = errors.Join(err, file.Close()) }()
	h := xxhash.New()
	w := bufio.NewWriterSize(io.MultiWriter(file, h), int(min(size, 16<<10)))
	var buf [rollingCatalogEntryBytes]byte
	copy(buf[:], rollingCatalogMagic)
	le.PutUint32(buf[8:], uint32(len(entries))) //nolint:gosec // G115: one entry per 16-bit partition ID.
	le.PutUint32(buf[12:], start)
	le.PutUint32(buf[16:], end)
	if _, err = w.Write(buf[:rollingCatalogHeader]); err != nil {
		return ref, err
	}
	for _, p := range entries {
		p.encode(buf[:])
		if _, err = w.Write(buf[:]); err != nil {
			return ref, err
		}
	}
	if err = w.Flush(); err != nil {
		return ref, err
	}
	return rollingReference(name, h.Sum64()), nil
}

func rollingBuildSlices(layouts []rollingLayout, width int) []rollingSlice {
	const n = rollingSlices
	var weights [rollingIDs + 1]uint64
	for _, p := range layouts {
		weights[int(p.id)+1] = p.size + uint64(p.count)*uint64(width) //nolint:gosec // G115: mask width is 1, 2, 4, or 8.
	}
	for i := 1; i <= rollingIDs; i++ {
		weights[i] += weights[i-1]
	}
	out := make([]rollingSlice, n)
	start := 0
	for i := range n - 1 {
		low, high := start+1, rollingIDs-(n-i-1)
		end := (i + 1) * rollingIDs / n
		if total := weights[rollingIDs]; total != 0 {
			weight := total/uint64(n)*uint64(i+1) + (total%uint64(n))*uint64(i+1)/uint64(n)
			end = low + sort.Search(high-low+1, func(j int) bool { return weights[low+j] >= weight })
			if end > low && (end > high || weight-weights[end-1] < weights[end]-weight) {
				end--
			}
		}
		out[i] = rollingSlice{Start: uint32(start), End: uint32(end)} //nolint:gosec // G115: boundaries are within [0, rollingIDs].
		start = end
	}
	out[n-1] = rollingSlice{Start: uint32(start), End: rollingIDs}
	return out
}

const rollingInstallSortMemory = 8 << 20

// BuildRolling installs name shards and ownership sidecars from canonical,
// possibly unsorted LF-delimited owner streams. The install alone sorts whole
// feeds on scratch storage; the streams and scratch runs are not retained.
// The new policy files are synced before returning the publishable manifest.
// The caller must create the store directory before building.
// Every build requires exclusive store ownership, serialized with sweeps.
// A rebuild advances the predecessor's sequence and folds every slice through it.
func BuildRolling(ctx context.Context, opt RollingOptions, workspace int64, owners map[string]func() (io.ReadCloser, error), previous *RollingManifest) (m RollingManifest, err error) {
	var sequence uint64
	if previous != nil {
		if previous.Sequence == math.MaxUint64 {
			return m, fmt.Errorf("%w: rolling sequence exhausted", errRolling)
		}
		sequence = previous.Sequence + 1
	}
	if err := context.Cause(ctx); err != nil {
		return m, err
	}
	width, err := rollingOwners(opt.Owners)
	if err != nil {
		return m, err
	}
	if opt.Dir == "" || len(owners) != len(opt.Owners) {
		return m, errRolling
	}
	for _, id := range opt.Owners {
		if owners[id] == nil {
			return m, fmt.Errorf("%w: missing owner %q", errRolling, id)
		}
	}
	// On Linux the final syncfs also flushes ancestor entries on this device.
	if previous == nil && !rollingUsesSyncfs {
		if err = syncRollingParents(opt.Dir, rollingDevice, syncRollingParent); err != nil {
			return m, err
		}
	}
	budget := min(rollingInstallSortMemory, max(2*MaxKey+16, rollingBudget(workspace)))
	runBuffer := 4 << 10
	if budget >= 1<<20 {
		runBuffer = 64 << 10
	}
	scratch, err := os.MkdirTemp(opt.Dir, rollingBuildPrefix)
	if err != nil {
		return m, err
	}
	files := rollingFiles{admitWrite: opt.AdmitWrite}
	defer func() {
		err = errors.Join(err, os.RemoveAll(scratch))
		if files.dir != nil {
			files.finish(&err)
		}
	}()
	type ownerRuns struct {
		owner, pass, count int
	}
	active := make([]ownerRuns, 0, len(opt.Owners))
	runName := func(owner, pass, run int) string {
		return filepath.Join(scratch, fmt.Sprintf("%d-%d-%d", owner, pass, run))
	}
	// Tighten the reader bound as nonempty streams are found. Keep opening
	// streams serially, and reduce the raw runs before opening the next one.
	var sorter rollingInstallSorter
	for i, id := range opt.Owners {
		if err := context.Cause(ctx); err != nil {
			return m, err
		}
		body, openErr := owners[id]()
		if openErr != nil {
			return m, openErr
		}
		if body == nil {
			return m, errRolling
		}
		scan := rollingScanner(body, 4<<10)
		runs, sortErr := sorter.sortRuns(ctx, scan, func(run int) string { return runName(i, 0, run) }, budget, opt.AdmitWrite, runBuffer)
		if err = errors.Join(sortErr, body.Close()); err != nil {
			return m, err
		}
		if runs == 0 {
			continue
		}
		active = append(active, ownerRuns{owner: i, count: runs})
		keep := min(fanIn, max(1, 2*fanIn/len(active)))
		for j := range active {
			r := &active[j]
			if r.count <= keep {
				continue
			}
			sorter.release()
			pass, count, _, err := reduceRuns(ctx, func(pass, run int) string {
				return runName(r.owner, r.pass+pass, run)
			}, r.count, keep, fanIn, 4<<10, opt.AdmitWrite)
			if err != nil {
				return m, err
			}
			r.pass, r.count = r.pass+pass, count
		}
	}
	sorter.release()
	pathCount := 0
	for _, r := range active {
		pathCount += r.count
	}
	type ownerRun struct {
		path string
		bit  uint64
	}
	paths := make([]ownerRun, 0, pathCount)
	for _, r := range active {
		for i := range r.count {
			paths = append(paths, ownerRun{runName(r.owner, r.pass, i), 1 << r.owner})
		}
	}
	// The sort arena has been released. Use a fraction of that budget for
	// read-ahead, bounded across all retained runs.
	readBuffer := max(4<<10, min(runBuffer, int(budget)/4/max(1, pathCount)))
	readers := make([]*rollingKeyReader, len(paths))
	read := func(visit func([]byte, uint64) error) error {
		return rollingReadMerged(ctx, readers, func(i int) (*rollingKeyReader, uint64, error) {
			run := paths[i]
			it, err := rollingReadKeys(run.path, readBuffer)
			return it, run.bit, err
		}, visit)
	}
	// The read phase merges the sorted runs to size the output partitions.
	layouts, count, err := rollingLayouts(read)
	if err != nil {
		return m, err
	}

	// Open before writing so Linux's syncfs can report intervening writeback errors.
	files.dir, err = os.Open(opt.Dir)
	if err != nil {
		return m, err
	}
	w := rollingBaseWriter{files: &files, output: rollingOutput{width: width}}
	defer w.close()
	entries := make([]rollingPartMeta, 0, len(layouts))
	finish := func() error {
		if w.part == nil {
			return nil
		}
		p, e := w.finish(ctx)
		if e == nil {
			entries = append(entries, p)
		}
		return e
	}
	err = read(func(key []byte, mask uint64) error {
		if w.part == nil || psnID(key) != w.layout.id {
			if e := finish(); e != nil {
				return e
			}
			if e := w.start(layouts[len(entries)]); e != nil {
				return e
			}
		}
		return w.output.add(key, mask)
	})
	if err != nil {
		return m, err
	}
	if err = finish(); err != nil {
		return m, err
	}
	ranges := rollingBuildSlices(layouts, width)
	for i := range ranges {
		if err := context.Cause(ctx); err != nil {
			return m, err
		}
		ranges[i].FoldedThrough = sequence
		n := sort.Search(len(entries), func(j int) bool { return uint32(entries[j].id) >= ranges[i].End })
		if ranges[i].Catalog, err = files.catalog(ranges[i].Start, ranges[i].End, entries[:n]); err != nil {
			return m, err
		}
		entries = entries[n:]
	}

	if err = files.sync(rollingSyncFiles); err != nil {
		return m, err
	}
	if err = context.Cause(ctx); err != nil {
		return m, err
	}
	m = RollingManifest{Version: rollingVersion, Owners: slices.Clone(opt.Owners), Slices: ranges, Sequence: sequence, Count: count}
	return m, nil
}

//nolint:gosec // G115: counts are bounded before encoding; segment offsets fit uint32, and salt deliberately wraps.
func (r *Rolling) writeSegment(ctx context.Context, files *rollingFiles, layouts []rollingLayout, count int, read func(func([]byte, uint64) error) error, union *int, available int64) (out rollingSegment, err error) {
	if count < 0 || uint64(count) > math.MaxUint32 {
		return out, errRolling
	}
	blocks := rollingFilterBlocks(uint32(count))
	if blocks != 0 {
		// Share the budget with the retained owner diffs. One word is the
		// minimum even when those diffs have consumed all budget.
		blocks = uint32(min(int64(blocks), max(1, available/8)))
	}
	filterSize := uint64(blocks) * 8
	header := uint64(rollingSegmentHeader) + (uint64(len(layouts))+1)*rollingSegmentEntryBytes
	size := header + filterSize
	for _, p := range layouts {
		size += p.size + uint64(p.count)*uint64(r.width)
		if size > psnMaxShardLength {
			return out, errRolling
		}
	}
	name := fmt.Sprintf(rollingSegmentPrefix+"%x"+rollingBinarySuffix, rollingNonce())
	f, err := files.create(name, size)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	salt := uint32(r.m.Sequence+1) * 0x9e3779b9
	w := bufio.NewWriterSize(f, 16<<10)
	var h [rollingSegmentHeader]byte
	copy(h[:], rollingSegmentMagic)
	le.PutUint32(h[8:], uint32(len(layouts)))
	le.PutUint32(h[12:], blocks)
	le.PutUint32(h[16:], salt)
	if _, err = w.Write(h[:]); err != nil {
		return out, err
	}
	off, index := header, uint32(0)
	var b [rollingSegmentEntryBytes]byte
	for _, p := range layouts {
		next := off + p.size + uint64(p.count)*uint64(r.width)
		le.PutUint16(b[:], p.id)
		le.PutUint32(b[2:], uint32(off))
		le.PutUint32(b[6:], index)
		if _, err = w.Write(b[:]); err != nil {
			return out, err
		}
		off, index = next, index+p.count
	}
	// The final directory entry ends the last run; consecutive offsets
	// and indexes describe each run's complete span and mask count.
	le.PutUint16(b[:], 0)
	le.PutUint32(b[2:], uint32(off))
	le.PutUint32(b[6:], index)
	if _, err = w.Write(b[:]); err != nil {
		return out, err
	}
	if err = w.Flush(); err != nil {
		return out, err
	}
	output := rollingOutput{width: r.width}
	var part int
	pos := header
	start := func(p rollingLayout) {
		output.start(f, f, int64(pos), int64(pos+p.size), p, false)
		pos += p.size + uint64(p.count)*uint64(r.width)
	}
	if len(layouts) != 0 {
		start(layouts[0])
	}
	filter := make([]byte, int(filterSize))
	err = read(func(key []byte, bits uint64) error {
		if part >= len(layouts) {
			return errRolling
		}
		if psnID(key) != layouts[part].id {
			if e := output.flush(layouts[part]); e != nil {
				return e
			}
			part++
			if part >= len(layouts) {
				return errRolling
			}
			start(layouts[part])
		}
		before := r.OwnerMask(key)
		after := before ^ bits
		if before == 0 {
			if *union == math.MaxInt {
				return errRolling
			}
			*union++
		}
		if after == 0 {
			*union--
		}
		h := xxhash.Sum64(key)
		o := rollingFilterOffset(uint32(h>>32), salt, blocks)
		le.PutUint64(filter[o:], le.Uint64(filter[o:])|rollingFilterBits(h))
		return output.add(key, after)
	})
	if err != nil {
		return out, err
	}
	if len(layouts) != 0 {
		if err = output.flush(layouts[part]); err != nil {
			return out, err
		}
	}
	if len(filter) != 0 {
		if _, err = f.WriteAt(filter, int64(off)); err != nil {
			return out, err
		}
	}
	var fileHash xxhash.Digest
	fileHash.Reset()
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return out, err
	}
	if _, err = io.CopyBuffer(&fileHash, rollingContextReader{ctx, f}, make([]byte, 32<<10)); err != nil {
		return out, err
	}
	sum := fileHash.Sum64()
	return rollingSegment{Sequence: r.m.Sequence + 1, Count: uint32(count), rollingFile: rollingReference(name, sum)}, nil
}

// Avoid file.WriteTo so the checksum observes cancellation between reads.
type rollingContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r rollingContextReader) Read(p []byte) (int, error) {
	if err := context.Cause(r.ctx); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// A rollingUpdate is a staged successor whose count was computed by applying
// the owner changes to the verified predecessor. It does not own the files
// or the predecessor, which must remain open until Open returns.
type rollingUpdate struct {
	store    *Rolling
	manifest RollingManifest
}

// Manifest returns a detached checkpoint for the caller to publish.
func (u rollingUpdate) Manifest() RollingManifest { return u.manifest.clone() }

// Open maps and validates the staged files. The count need not be reconstructed:
// the manifest is the private result of applying the changes, not caller input.
func (u rollingUpdate) Open(ctx context.Context) (*Rolling, error) {
	if u.store == nil || len(u.store.catalog) == 0 {
		return nil, errRolling
	}
	return openRolling(ctx, u.store.dir, u.store.m.Owners, u.manifest, u.store, true)
}

// Apply stages and syncs a successor without changing the current view.
func (f *RollingRefresh) Apply(ctx context.Context, changes []*RollingChange) (rollingUpdate, error) {
	m, err := f.apply(ctx, changes, rollingSyncFiles)
	if err != nil {
		return rollingUpdate{}, err
	}
	return rollingUpdate{store: f.store, manifest: m}, nil
}

func (f *RollingRefresh) apply(ctx context.Context, changes []*RollingChange, syncFiles func(*os.File, []string) error) (m RollingManifest, err error) {
	if err := context.Cause(ctx); err != nil {
		return m, err
	}
	r := f.store
	if len(r.catalog) == 0 || r.m.Sequence == math.MaxUint64 {
		return m, errRolling
	}
	var changed uint64
	for _, c := range changes {
		if c == nil || c.refresh != f || changed&(1<<c.owner) != 0 {
			return m, fmt.Errorf("%w: duplicate or stale owner diff", errRolling)
		}
		changed |= 1 << c.owner
	}
	readers := make([]*rollingKeyReader, len(changes))
	read := func(visit func([]byte, uint64) error) error {
		return rollingReadMerged(ctx, readers, func(i int) (*rollingKeyReader, uint64, error) {
			c := changes[i]
			it, err := c.reader()
			return it, 1 << c.owner, err
		}, visit)
	}
	layouts, n, err := rollingLayouts(read)
	if err != nil {
		return m, err
	}

	dir, err := os.Open(r.dir)
	if err != nil {
		return m, err
	}
	files := rollingFiles{dir: dir, admitWrite: f.admitWrite}
	defer files.finish(&err)
	m = r.m
	m.Slices = slices.Clone(m.Slices)
	m.Segments = make([]rollingSegment, len(r.m.Segments)+1)
	copy(m.Segments, r.m.Segments)
	seg, err := r.writeSegment(ctx, &files, layouts, n, read, &m.Count, f.budget-f.retained)
	if err != nil {
		return m, err
	}
	m.Sequence, m.Segments[len(m.Segments)-1] = seg.Sequence, seg

	// This mapping is for folding. If the segment survives, rollingUpdate.Open
	// validates it at its final pathname before publication.
	data, err := rollingMapReference(ctx, r.dir, rollingSegmentPrefix, seg.rollingFile)
	if err != nil {
		return m, err
	}
	defer unmapFile(data)
	pending := rollingSegmentMap{data: data, width: r.width}
	if err = pending.validate(ctx, seg.Count, len(m.Owners)); err != nil {
		return m, err
	}
	segments := make([]rollingSegmentMap, len(r.segments)+1)
	copy(segments, r.segments)
	segments[len(r.segments)] = pending
	next := Rolling{m: m, width: r.width, base: r.base, segments: segments}
	if err = next.index(ctx); err != nil {
		return m, err
	}
	var perSlice [rollingSlices]int64
	var pendingEntries int64
	for _, p := range next.parts {
		if p.start == p.end {
			continue
		}
		idx := next.sliceFor(p.id)
		for _, o := range next.overlay[p.start:p.end] {
			count := int64(next.segments[o.segment].count(int(o.run)))
			perSlice[idx] += count
			pendingEntries += count
		}
	}

	// Reserve one quarter of the refresh budget at an estimated eight
	// bytes per pending operation. Drain sequentially, never skip slices.
	limit, remaining := f.budget/32, pendingEntries-perSlice[m.Cursor]
	fold := 1
	for fold < len(m.Slices) && remaining > limit {
		remaining -= perSlice[(m.Cursor+fold)%len(m.Slices)]
		fold++
	}
	if err = r.foldPartitions(ctx, &next, &files, fold, &perSlice); err != nil {
		return m, err
	}
	m.Cursor = (m.Cursor + fold) % len(m.Slices)
	through := m.Sequence
	for _, s := range m.Slices {
		through = min(through, s.FoldedThrough)
	}
	drop := sort.Search(len(m.Segments), func(i int) bool { return m.Segments[i].Sequence > through })
	clear(m.Segments[:drop])
	m.Segments = m.Segments[drop:]
	if drop == len(segments) {
		if err = os.Remove(filepath.Join(r.dir, seg.Name)); err != nil {
			return m, err
		}
		files.names = slices.Delete(files.names, 0, 1) // The segment was staged first.
	}

	if err = context.Cause(ctx); err != nil {
		return m, err
	}

	if err = files.sync(syncFiles); err != nil {
		return m, err
	}
	if err = context.Cause(ctx); err != nil {
		return m, err
	}
	return m, nil
}

func (r *Rolling) foldPartitions(ctx context.Context, next *Rolling, files *rollingFiles, fold int, perSlice *[rollingSlices]int64) error {
	w := rollingBaseWriter{files: files, output: rollingOutput{width: r.width}}
	defer w.close()
	var entries []rollingPartMeta
	for i := range fold {
		idx := (next.m.Cursor + i) % len(next.m.Slices)
		s := &next.m.Slices[idx]
		s.FoldedThrough = next.m.Sequence
		if perSlice[idx] == 0 {
			continue
		}
		start := sort.Search(len(next.parts), func(j int) bool { return uint32(next.parts[j].id) >= s.Start })
		end := start + sort.Search(len(next.parts)-start, func(j int) bool { return uint32(next.parts[start+j].id) >= s.End })
		var updated bool
		var err error
		entries, updated, err = r.foldSlice(ctx, next, next.parts[start:end], r.catalog[idx], &w, entries[:0])
		if err != nil {
			return err
		}
		if updated {
			if s.Catalog, err = files.catalog(s.Start, s.End, entries); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Rolling) foldSlice(ctx context.Context, next *Rolling, parts []rollingLookup, catalog rollingCatalogMap, w *rollingBaseWriter, entries []rollingPartMeta) ([]rollingPartMeta, bool, error) {
	updated := false
	var merge rollingPartMerge
	var base rollingPartCursor
	var measure rollingMeasure
	for _, p := range parts {
		if err := context.Cause(ctx); err != nil {
			return nil, false, err
		}
		if p.start == p.end {
			if p.base >= 0 {
				entries = append(entries, catalog.entry(int(p.base)-catalog.first))
			}
			continue
		}
		next.mergePart(&merge, p)
		measure.reset(p.id)
		same := p.base >= 0
		if same {
			base.start(r.base[p.base])
		}
		for n, v := 0, merge.next(); v != nil; n, v = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return nil, false, context.Cause(ctx)
			}
			mask := v.run.mask(v.index, r.width)
			if mask == 0 {
				continue
			}
			if same {
				same = !base.exhausted() && bytes.Equal(base.key, v.key) && base.run.mask(base.index, r.width) == mask
				if same {
					base.advance()
				}
			}
			if err := measure.add(v.key); err != nil {
				return nil, false, err
			}
		}
		if same && base.exhausted() {
			entries = append(entries, catalog.entry(int(p.base)-catalog.first))
			continue
		}
		if measure.layout.count == 0 {
			updated = updated || p.base >= 0
			continue
		}
		if err := w.start(measure.layout); err != nil {
			return nil, false, err
		}
		next.mergePart(&merge, p)
		for n, v := 0, merge.next(); v != nil; n, v = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return nil, false, context.Cause(ctx)
			}
			if mask := v.run.mask(v.index, r.width); mask != 0 {
				if err := w.output.add(v.key, mask); err != nil {
					return nil, false, err
				}
			}
		}
		out, err := w.finish(ctx)
		if err != nil {
			return nil, false, err
		}
		entries = append(entries, out)
		updated = true
	}
	return entries, updated, nil
}

func rollingBudget(workspace int64) int64 {
	return min(max(0, workspace), int64(^uint32(0)))
}

func rollingNonce() (n [16]byte) {
	_, _ = rand.Read(n[:])
	return n
}

type rollingFiles struct {
	dir        *os.File
	names      []string
	admitWrite func(oldSize, newSize uint64) error
}

func (f *rollingFiles) create(name string, size uint64) (*os.File, error) {
	if f.admitWrite != nil {
		if err := f.admitWrite(0, size); err != nil {
			return nil, err
		}
	}
	out, err := os.OpenFile(filepath.Join(f.dir.Name(), name), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600) //nolint:gosec // G304: generated basename in the store directory.
	if err == nil {
		f.names = append(f.names, name)
	}
	return out, err
}

func (f *rollingFiles) finish(err *error) {
	if closeErr := f.dir.Close(); closeErr != nil {
		*err = errors.Join(*err, closeErr)
	}
	if *err == nil {
		return
	}
	for _, name := range f.names {
		_ = os.Remove(filepath.Join(f.dir.Name(), name))
	}
}

func (f *rollingFiles) sync(syncFiles func(*os.File, []string) error) error {
	if err := syncFiles(f.dir, f.names); err != nil {
		return fmt.Errorf("sync rolling data: %w", err)
	}
	if rollingUsesSyncfs {
		return nil
	}
	return f.dir.Sync()
}

func syncRollingParents(dir string, device func(string) (uint64, error), syncDir func(string) error) error {
	storeDev, err := device(dir)
	if err != nil {
		return fmt.Errorf("stat compact store %s: %w", dir, err)
	}
	for parent := filepath.Dir(dir); parent != dir; parent = filepath.Dir(dir) {
		dev, err := device(parent)
		if err != nil {
			return fmt.Errorf("stat compact store ancestor %s: %w", parent, err)
		}
		if dev != storeDev {
			break
		}
		if err := syncDir(parent); err != nil {
			return fmt.Errorf("sync compact store ancestor %s: %w", parent, err)
		}
		dir = parent
	}
	return nil
}

func syncRollingParent(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304: parent of the store directory.
	if runtime.GOOS == "darwin" && errors.Is(err, syscall.EACCES) {
		// Darwin O_SEARCH opens a searchable directory without read permission.
		const darwinOSearch = 0x40100000
		f, err = os.OpenFile(path, darwinOSearch, 0) //nolint:gosec // G304: parent of the store directory.
	}
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func rollingReference(name string, sum uint64) rollingFile {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sum)
	var encoded [16]byte
	hex.Encode(encoded[:], b[:])
	return rollingFile{Name: name, XXH64: string(encoded[:])}
}

// Shard encoding and decoding.

// A shard stores a count, uint32 block offsets, and front-coded records
// with a full key every 16 records. Offsets are relative to the shard.
const (
	psnBlock          = 16
	psnMaxShardLength = min(1<<32-1, uint64(^uint(0)>>1))
	psnMaxVarintBytes = 3 // MaxKey fits in three 7-bit groups.
)

// MaxKey is the maximum canonical key length in bytes.
const MaxKey = 65535

var (
	le           = binary.LittleEndian
	errPartition = errors.New("compactset: invalid name partition")
)

type psnPartition struct {
	id    uint16
	count uint32
	data  []byte
}

func psnID(k []byte) uint16 {
	var id uint16
	if len(k) > 0 {
		id = uint16(k[0]) << 8
	}
	if len(k) > 1 {
		id |= uint16(k[1])
	}
	return id
}

var psnNewline = [1]byte{'\n'}

func psnVarintSize(n int) int {
	if n < 1<<7 {
		return 1
	}
	if n < 1<<14 {
		return 2
	}
	return 3
}

func psnRecordPrefix(previous, key []byte, count uint32) int {
	if count%psnBlock == 0 {
		return 0
	}
	n := min(len(previous), len(key))
	i := 0
	for i < n && previous[i] == key[i] {
		i++
	}
	return i
}

func psnBlockCount(count uint32) int {
	return int((uint64(count) + psnBlock - 1) / psnBlock) //nolint:gosec // G115: at most 1<<28 blocks.
}

// Both write buffers stay fixed-size even if every rule lies in one shard.
// Block offsets and records are streamed into disjoint ranges of that file.
type psnWriter struct {
	offsets, records *bufio.Writer
	header           [2 * psnMaxVarintBytes]byte
	offset           [4]byte
	prev             []byte
	count            uint32
	pos              uint64
}

func (w *psnWriter) add(key []byte) error {
	prefix := psnRecordPrefix(w.prev, key, w.count)
	suffix := key[prefix:]
	b := w.header[:]
	n := binary.PutUvarint(b, uint64(prefix)) //nolint:gosec // G115: prefix is a length in key.
	n += binary.PutUvarint(b[n:], uint64(len(suffix)))
	next := w.pos + uint64(n+len(suffix)) //nolint:gosec // G115: both summands are byte lengths.
	if next > psnMaxShardLength {
		return errPartition
	}
	if w.count%psnBlock == 0 {
		le.PutUint32(w.offset[:], uint32(w.pos)) //nolint:gosec // G115: w.pos is below next, which fits uint32.
		if _, err := w.offsets.Write(w.offset[:]); err != nil {
			return err
		}
	}
	if _, err := w.records.Write(b[:n]); err != nil {
		return err
	}
	if _, err := w.records.Write(suffix); err != nil {
		return err
	}
	w.pos = next
	w.count++
	w.prev = append(w.prev[:0], key...)
	return nil
}

func psnMinSize(count uint32) int64 {
	return 4 + int64(psnBlockCount(count))*4 + int64(count)*2
}

func (p *psnPartition) offset(block int) int { return int(le.Uint32(p.data[4+block*4:])) }

func (p *psnPartition) firstInBlock(block int) []byte {
	pos := p.offset(block)
	_, n, width := psnRecordLengths(p.data[pos:])
	start := pos + width
	return p.data[start : start+n]
}

// A zero width denotes a truncated, non-canonical, or out-of-range length.
func psnReadVarint(data []byte) (value, width int) {
	if len(data) == 0 {
		return 0, 0
	}
	first := int(data[0])
	if first < 1<<7 {
		return first, 1
	}
	value = first & 0x7f
	for i := 1; i < min(len(data), psnMaxVarintBytes); i++ {
		b := int(data[i])
		value |= (b & 0x7f) << (7 * i)
		if b < 1<<7 {
			if b == 0 || value > MaxKey {
				return 0, 0
			}
			return value, i + 1
		}
	}
	return 0, 0
}
func psnRecordLengths(data []byte) (prefix, suffix, width int) {
	if len(data) >= 2 && data[0]|data[1] < 0x80 {
		return int(data[0]), int(data[1]), 2
	}
	return psnReadVarintLengths(data)
}

func psnReadVarintLengths(data []byte) (prefix, suffix, width int) {
	prefix, a := psnReadVarint(data)
	if a == 0 {
		return 0, 0, 0
	}
	suffix, b := psnReadVarint(data[a:])
	if b == 0 {
		return 0, 0, 0
	}
	return prefix, suffix, a + b
}

type psnKeyValidator struct {
	key    [MaxKey + 1]byte
	pos, n int
}

func (v *psnKeyValidator) start(count uint32) {
	v.pos, v.n = 4+4*psnBlockCount(count), 0
}

func (v *psnKeyValidator) next(p *psnPartition, i uint32) []byte {
	data := p.data[v.pos:]
	prefix, suffix, width := psnRecordLengths(data)
	if width == 0 || prefix > v.n || suffix > len(data)-width || prefix+suffix > MaxKey {
		return nil
	}
	if i%psnBlock == 0 && (prefix != 0 || p.offset(int(i/psnBlock)) != v.pos) {
		return nil
	}
	tail := data[width : width+suffix]
	// Compare before replacing the suffix. An inherited prefix was already
	// validated, and is identical in the old and new keys.
	if (i > 0 && bytes.Compare(v.key[prefix:v.n], tail) >= 0) || bytes.IndexByte(tail, '\n') >= 0 {
		return nil
	}
	v.n = prefix + suffix
	key := v.key[:v.n]
	copy(key[prefix:], tail)
	if psnID(key) != p.id {
		return nil
	}
	v.pos += width + suffix
	return key
}

func (p *psnPartition) checkedKeysDigest(ctx context.Context) (uint64, error) {
	if le.Uint32(p.data) != p.count {
		return 0, errPartition
	}
	var v psnKeyValidator
	v.start(p.count)
	h := xxhash.New()
	for i := range p.count {
		if i&1023 == 0 && ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		key := v.next(p, i)
		if key == nil {
			return 0, errPartition
		}
		// Hash the same LF-delimited keys as the writer, without a second
		// hash call. A record's retained prefix never includes this byte.
		key = append(key, '\n')
		_, _ = h.Write(key)
	}
	if v.pos != len(p.data) {
		return 0, errPartition
	}
	return h.Sum64(), nil
}

func (p *psnPartition) findInBlock(block int, key []byte) int {
	if len(key) <= 512 {
		var b [512]byte
		return p.searchBlock(block, key, b[:len(key)])
	}
	return p.findInLongBlock(block, key)
}
func (p *psnPartition) findInLongBlock(block int, key []byte) int {
	var b [MaxKey]byte
	return p.searchBlock(block, key, b[:len(key)])
}
func (p *psnPartition) searchBlock(block int, key, b []byte) int {
	pos, n := p.offset(block), 0
	for i := range min(psnBlock, int(p.count)-block*psnBlock) {
		// These offsets and record lengths were checked when the run was mapped.
		prefix, suffix, width := psnRecordLengths(p.data[pos:])
		pos += width
		copy(b[min(prefix, len(b)):], p.data[pos:pos+suffix])
		pos, n = pos+suffix, prefix+suffix
		cmp := bytes.Compare(b[:min(n, len(b))], key)
		if cmp == 0 && n == len(key) {
			return i
		}
		if cmp > 0 || (cmp == 0 && n > len(key)) {
			break
		}
	}
	return -1
}

// Bounded external sorting.

const fanIn = 16

func rollingScanner(r io.Reader, size int) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, size), MaxKey+2)
	s.Split(splitKeyLine)
	return s
}

// Unlike bufio.ScanLines, splitKeyLine preserves a trailing carriage return.
func splitKeyLine(data []byte, atEOF bool) (int, []byte, error) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

type span struct{ start, end uint32 }

const spanBytes = int64(unsafe.Sizeof(span{}))

type rollingInstallSorter struct {
	arena  []byte
	spans  []span
	writer *bufio.Writer
}

func (s *rollingInstallSorter) release() {
	if s.writer != nil {
		// Release the sort backing stores before opening merge readers.
		*s = rollingInstallSorter{}
		runtime.GC()
	}
}

// sortRuns produces runs that are unique internally, not necessarily across runs.
func (s *rollingInstallSorter) sortRuns(ctx context.Context, scan *bufio.Scanner, name func(int) string, memory int64, admit func(uint64, uint64) error, bufferSize int) (int, error) {
	if !scan.Scan() {
		return 0, scan.Err()
	}
	if s.writer == nil {
		// Charge run buffering beyond 4 KiB to the arena.
		memory -= int64(bufferSize - 4096)
		s.arena = make([]byte, 0, int(memory/2))
		s.spans = make([]span, 0, int(memory/2/spanBytes))
		s.writer = bufio.NewWriterSize(io.Discard, bufferSize)
	}
	workers := rollingWorkers()
	w, arena, spans := s.writer, s.arena, s.spans
	defer w.Reset(io.Discard)
	runs := 0
	flush := func() error {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		sortRunSpans(arena, spans, workers)
		f, e := os.Create(name(runs)) //nolint:gosec // G304: generated run name inside the private build directory.
		if e != nil {
			return e
		}
		w.Reset(admitRunWrites(f, admit))
		var prev []byte
		var header [4]byte
		for i, s := range spans {
			if i&1023 == 0 && ctx.Err() != nil {
				e = context.Cause(ctx)
				break
			}
			b := arena[s.start:s.end]
			if prev != nil && bytes.Equal(prev, b) {
				continue
			}
			if e = writeRecord(w, b, &header); e != nil {
				break
			}
			prev = b
		}
		if e == nil {
			e = w.Flush()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return e
		}
		runs++
		arena = arena[:0]
		spans = spans[:0]
		return nil
	}
	for n, more := 0, true; more; n, more = n+1, scan.Scan() {
		if n&1023 == 0 && ctx.Err() != nil {
			return 0, context.Cause(ctx)
		}
		b := scan.Bytes()
		if len(b) > MaxKey {
			return 0, fmt.Errorf("compactset: key exceeds %d bytes", MaxKey)
		}
		if len(arena)+len(b) > cap(arena) || len(spans) == cap(spans) {
			if err := flush(); err != nil {
				return 0, err
			}
		}
		if len(b) > cap(arena) {
			return 0, fmt.Errorf("compactset: key exceeds sort chunk budget")
		}
		start := len(arena)
		arena = append(arena, b...)
		spans = append(spans, span{uint32(start), uint32(len(arena))}) //nolint:gosec // G115: the install arena is at most 8 MiB.
	}
	if err := scan.Err(); err != nil {
		return 0, err
	}
	if err := flush(); err != nil {
		return 0, err
	}
	return runs, nil
}

func sortRunSpans(arena []byte, spans []span, workers int) {
	compare := func(a, b span) int {
		return bytes.Compare(arena[a.start:a.end], arena[b.start:b.end])
	}
	if workers < 2 || len(spans) < 4096 {
		slices.SortFunc(spans, compare)
		return
	}
	// Split the existing arena's index in place. Exclude equal keys so a
	// duplicate-heavy feed cannot consume all the work in one child.
	a, pivot, c := spans[len(spans)/4], spans[len(spans)/2], spans[len(spans)*3/4]
	if compare(a, pivot) > 0 {
		a, pivot = pivot, a
	}
	if compare(pivot, c) > 0 {
		pivot = c
		if compare(a, pivot) > 0 {
			pivot = a
		}
	}
	lo, hi := 0, len(spans)
	for i := 0; i < hi; {
		switch d := compare(spans[i], pivot); {
		case d < 0:
			spans[lo], spans[i] = spans[i], spans[lo]
			lo++
			i++
		case d > 0:
			hi--
			spans[hi], spans[i] = spans[i], spans[hi]
		default:
			i++
		}
	}
	left, right := spans[:lo], spans[hi:]
	if len(left) < 2048 || len(right) < 2048 {
		slices.SortFunc(left, compare)
		slices.SortFunc(right, compare)
		return
	}
	done := make(chan struct{})
	go func() {
		slices.SortFunc(left, compare)
		close(done)
	}()
	slices.SortFunc(right, compare)
	<-done
}

func writeRecord(w io.Writer, b []byte, h *[4]byte) error {
	le.PutUint32(h[:], uint32(len(b))) //nolint:gosec // G115: input and scratch readers bound keys to MaxKey.
	if _, e := w.Write(h[:]); e != nil {
		return e
	}
	_, e := w.Write(b)
	return e
}

// Reduce runs in numbered passes without retaining a list of all spill paths.
func reduceRuns(ctx context.Context, name func(pass, run int) string, runs, keep, fan, bufSize int, admit func(uint64, uint64) error) (pass, remaining, records int, err error) {
	for ; runs > keep; pass++ {
		out := 0
		for first := 0; first < runs; first += fan {
			if err := context.Cause(ctx); err != nil {
				return 0, 0, 0, err
			}
			var batch [fanIn]string
			paths := batch[:min(fan, runs-first)]
			for i := range paths {
				paths[i] = name(pass, first+i)
			}
			records, err = mergeRuns(ctx, paths, name(pass+1, out), bufSize, admit)
			if err != nil {
				return 0, 0, 0, err
			}
			for _, path := range paths {
				if err := os.Remove(path); err != nil {
					return 0, 0, 0, err
				}
			}
			out++
		}
		runs = out
	}
	return pass, runs, records, nil
}

func mergeRuns(ctx context.Context, paths []string, out string, bufSize int, admit func(uint64, uint64) error) (count int, err error) {
	f, err := os.Create(out) //nolint:gosec // G304: generated merge run in the private scratch directory.
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	w := bufio.NewWriterSize(admitRunWrites(f, admit), bufSize)
	var header [4]byte
	var readers [fanIn]*rollingKeyReader
	if err := rollingReadMerged(ctx, readers[:len(paths)], func(i int) (*rollingKeyReader, uint64, error) {
		it, err := rollingReadKeys(paths[i], bufSize)
		return it, 0, err
	}, func(key []byte, _ uint64) error {
		count++
		return writeRecord(w, key, &header)
	}); err != nil {
		return 0, err
	}
	return count, w.Flush()
}

func rollingReadMerged(ctx context.Context, readers []*rollingKeyReader, open func(int) (*rollingKeyReader, uint64, error), visit func([]byte, uint64) error) error {
	defer func() {
		for _, it := range readers {
			it.close()
		}
		clear(readers)
	}()
	for i := range readers {
		it, bit, err := open(i)
		if err != nil {
			readers = readers[:i]
			return err
		}
		it.bit = bit
		readers[i] = it
	}
	for n := 0; ; n++ {
		if n&1023 == 0 && ctx.Err() != nil {
			return context.Cause(ctx)
		}
		first := -1
		for i, it := range readers {
			if it.err != nil {
				return it.err
			}
			if it.valid && (first < 0 || bytes.Compare(it.key, readers[first].key) < 0) {
				first = i
			}
		}
		if first < 0 {
			return nil
		}
		it := readers[first]
		mask := it.bit
		for i := first + 1; i < len(readers); i++ {
			next := readers[i]
			if next.valid && bytes.Equal(it.key, next.key) {
				mask |= next.bit
				next.advance()
			}
		}
		if err := visit(it.key, mask); err != nil {
			return err
		}
		it.advance()
	}
}

func admitRunWrites(w io.Writer, admit func(uint64, uint64) error) io.Writer {
	if admit == nil {
		return w
	}
	return &admittedRunWriter{out: w, admit: admit}
}

type admittedRunWriter struct {
	out   io.Writer
	admit func(uint64, uint64) error
	size  uint64
}

func (w *admittedRunWriter) Write(p []byte) (int, error) {
	if err := w.admit(w.size, w.size+uint64(len(p))); err != nil {
		return 0, err
	}
	n, err := w.out.Write(p)
	w.size += uint64(n) //nolint:gosec // G115: io.Writer returns a nonnegative byte count.
	return n, err
}

// A sorted key source (in memory or scratch) also carries an owner bit for
// multi-owner merges. Readers reuse key and length storage across records.
type rollingKeyReader struct {
	key    []byte
	valid  bool
	err    error
	file   *os.File
	input  *bufio.Reader
	header [4]byte
	arena  []byte
	spans  []span
	bit    uint64
	ranges []rollingKeySet
}

func rollingReadKeys(path string, size int) (*rollingKeyReader, error) {
	it := &rollingKeyReader{}
	if err := it.openRun(path, size); err != nil {
		return nil, err
	}
	it.advance()
	return it, nil
}

func (it *rollingKeyReader) openRun(path string, size int) error {
	f, err := os.Open(path) //nolint:gosec // G304: generated run in the private scratch directory.
	if err != nil {
		return err
	}
	it.file = f
	if it.input == nil {
		it.input = bufio.NewReaderSize(f, size)
	} else {
		it.input.Reset(f)
	}
	return nil
}

func (it *rollingKeyReader) close() {
	if it.file != nil {
		_ = it.file.Close()
	}
	it.file = nil
}

func (it *rollingKeyReader) advance() {
	it.valid = false
	it.advanceKey()
	for !it.valid && it.err == nil && len(it.ranges) != 0 {
		it.close()
		it.key = nil // The previous key may alias an in-memory range.
		p := &it.ranges[0]
		it.ranges = it.ranges[1:]
		it.arena, it.spans = p.arena, p.spans
		if p.path != "" {
			if it.err = it.openRun(p.path, 4<<10); it.err != nil {
				return
			}
		}
		it.advanceKey()
	}
}

func (it *rollingKeyReader) advanceKey() {
	if it.file == nil {
		if len(it.spans) == 0 {
			return
		}
		s := it.spans[0]
		it.spans = it.spans[1:]
		it.key, it.valid = it.arena[s.start:s.end], true
		return
	}
	if _, err := io.ReadFull(it.input, it.header[:]); err != nil {
		if err != io.EOF {
			it.err = err
		}
		return
	}
	n := le.Uint32(it.header[:])
	if n > MaxKey {
		it.err = errRolling
		return
	}
	if int(n) > cap(it.key) {
		it.key = make([]byte, max(int(n), min(MaxKey, max(256, 2*cap(it.key)))))
	}
	it.key = it.key[:n]
	_, it.err = io.ReadFull(it.input, it.key)
	if it.err == io.EOF {
		it.err = io.ErrUnexpectedEOF
	}
	it.valid = it.err == nil
}
