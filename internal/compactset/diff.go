package compactset

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
)

// RollingRefresh stages a single, serial batch of owner diffs for one view.
// Close each returned change when it is no longer needed.
type RollingRefresh struct {
	store      *Rolling
	budget     int64
	retained   int64
	admitWrite func(oldSize, newSize uint64) error
}

// BeginRefresh fixes the memory budget for all diffs and the fold.
// admitWrite has the same contract as RollingOptions.AdmitWrite and is shared
// by all scratch and policy files created by this refresh.
func (r *Rolling) BeginRefresh(workspace int64, admitWrite func(oldSize, newSize uint64) error) *RollingRefresh {
	return &RollingRefresh{store: r, budget: rollingBudget(workspace), admitWrite: admitWrite}
}

const (
	rollingDiffChunkMax  = 24 << 20
	rollingDiffChunkSeed = 16 << 10
)

// RollingChange holds the unique changes for one full owner body, bound to the
// refresh that produced it. Close releases its scratch after Apply, or if it
// is discarded. Apply does not consume it.
type RollingChange struct {
	refresh *RollingRefresh
	owner   int
	ranges  []rollingKeySet
	dir     string
	// Adds and Removes count owner membership changes.
	Adds, Removes int
}

// Close releases the diff's memory and removes its scratch files.
func (c *RollingChange) Close() error {
	if c.refresh != nil {
		c.refresh.retained -= c.retainedBytes()
	}
	c.ranges, c.refresh = nil, nil
	if c.dir == "" {
		return nil
	}
	err := os.RemoveAll(c.dir)
	if err == nil {
		c.dir = ""
	}
	return err
}

func (c *RollingChange) retainedBytes() (n int64) {
	for i := range c.ranges {
		n += c.ranges[i].retainedBytes()
	}
	return n
}

func (c *RollingChange) reader() (*rollingKeyReader, error) {
	it := &rollingKeyReader{ranges: c.ranges}
	it.advance()
	if it.err != nil {
		it.close()
		return nil, it.err
	}
	return it, nil
}

type rollingKeySet struct {
	arena []byte
	spans []span
	path  string
}

func (k *rollingKeySet) retainedBytes() int64 {
	return int64(cap(k.arena)) + spanBytes*int64(cap(k.spans))
}

type rollingSeen struct {
	start, end int
	bits       []byte
}

func (s *rollingSeen) mark(index int) {
	i := index - s.start
	s.bits[i/8] |= 1 << (i % 8)
}

func (s *rollingSeen) has(index int) bool {
	i := index - s.start
	return s.bits[i/8]&(1<<(i%8)) != 0
}

func (s *rollingSeen) nextUnseen(ctx context.Context, index, end int) int {
	i := index - s.start
	last := end - s.start
	if i < last {
		b := ^s.bits[i/8] >> (i % 8)
		if b != 0 {
			return min(end, index+bits.TrailingZeros8(b))
		}
		for j := i/8 + 1; j*8 < last; j++ {
			if j&4095 == 0 && ctx.Err() != nil {
				return end
			}
			if b := ^s.bits[j]; b != 0 {
				return min(end, s.start+j*8+bits.TrailingZeros8(b))
			}
		}
	}
	return end
}

type rollingPartCursor struct {
	run        rollingRun
	key        []byte
	pos, index int
	source     int
}

func (c *rollingPartCursor) start(run rollingRun) {
	c.rewind(run)
	c.advance()
}

func (c *rollingPartCursor) rewind(run rollingRun) {
	c.run, c.index = run, -1
	c.pos = 4 + 4*psnBlockCount(run.part.count)
	c.key = c.key[:0]
}

func (c *rollingPartCursor) advance() {
	c.index++
	if c.exhausted() {
		return
	}
	// Run validation ensures every block starts with a zero prefix length.
	rec := c.run.part.data[c.pos:]
	prefix, suffix, width := psnRecordLengths(rec)
	n := prefix + suffix
	if n > cap(c.key) {
		b := make([]byte, n, max(n, min(MaxKey, max(256, 2*cap(c.key)))))
		copy(b, c.key[:prefix])
		c.key = b
	}
	c.key = c.key[:n]
	copy(c.key[prefix:], rec[width:width+suffix])
	c.pos += width + suffix
}

func (c *rollingPartCursor) exhausted() bool { return c.index >= int(c.run.part.count) }

// seek tests ordered keys against a validated run. Keep the decoded key
// between probes and skip blocks whose keys cannot match the next probe.
func (c *rollingPartCursor) seek(key []byte) bool {
	if c.exhausted() {
		return false
	}
	part := &c.run.part
	next := c.index/psnBlock + 1
	blocks := psnBlockCount(part.count)
	if next < blocks && bytes.Compare(part.firstInBlock(next), key) <= 0 {
		block := next + sort.Search(blocks-next-1, func(i int) bool {
			return bytes.Compare(part.firstInBlock(next+1+i), key) > 0
		})
		c.pos, c.index = part.offset(block), block*psnBlock-1
		c.advance()
	}
	if c.index < 0 {
		c.advance()
	}
	for !c.exhausted() {
		if cmp := bytes.Compare(c.key, key); cmp >= 0 {
			return cmp == 0
		}
		c.advance()
	}
	return false
}

func (c *rollingPartCursor) advanceUnseen(ctx context.Context, seen *rollingSeen) {
	end := c.run.index + int(c.run.part.count)
	target := seen.nextUnseen(ctx, c.run.index+c.index+1, end) - c.run.index
	if target == int(c.run.part.count) {
		c.index = target
		return
	}
	if block := target / psnBlock; block != c.index/psnBlock {
		c.pos, c.index = c.run.part.offset(block), block*psnBlock-1
	}
	for c.index < target {
		c.advance()
	}
}

// Only overlay runs enter the heap. Equal keys prefer the newer cursor,
// including when its record is a tombstone. The larger base run is merged
// separately so advancing it never touches the heap.
type rollingPartMerge struct {
	base          rollingPartCursor
	cursors       []rollingPartCursor
	heap          []int
	shadowed      []rollingSeen
	unseen        []rollingSeen
	unseenContext context.Context
	baseWon       bool
	hasBase       bool
	started       bool
}

func (m *rollingPartMerge) reset() {
	m.heap, m.started = m.heap[:0], false
	m.baseWon, m.hasBase = false, false
}

func (m *rollingPartMerge) add(run rollingRun, source int) {
	i := len(m.heap)
	if i == len(m.cursors) {
		m.cursors = append(m.cursors, rollingPartCursor{})
	}
	c := &m.cursors[i]
	c.rewind(run)
	c.source = source
	m.step(c)
	if !c.exhausted() {
		m.heap = append(m.heap, i)
	}
}

func (m *rollingPartMerge) step(c *rollingPartCursor) {
	if m.unseen == nil {
		c.advance()
	} else {
		c.advanceUnseen(m.unseenContext, &m.unseen[c.source])
	}
}

func (m *rollingPartMerge) shadow(c *rollingPartCursor) {
	if m.shadowed != nil {
		m.shadowed[c.source].mark(c.run.index + c.index)
	}
}

func (m *rollingPartMerge) less(a, b int) bool {
	cmp := bytes.Compare(m.cursors[a].key, m.cursors[b].key)
	return cmp < 0 || (cmp == 0 && a < b)
}

func (m *rollingPartMerge) siftDown(i int) {
	root := m.heap[i]
	for child := 2*i + 1; child < len(m.heap); child = 2*i + 1 {
		if right := child + 1; right < len(m.heap) && m.less(m.heap[right], m.heap[child]) {
			child = right
		}
		if !m.less(m.heap[child], root) {
			break
		}
		m.heap[i], i = m.heap[child], child
	}
	m.heap[i] = root
}

// Only the root or a child tied with it is advanced. An exhausted child can
// therefore be replaced with the last heap entry without sifting up.
func (m *rollingPartMerge) advance(i int) {
	c := &m.cursors[m.heap[i]]
	m.step(c)
	if c.exhausted() {
		last := len(m.heap) - 1
		m.heap[i] = m.heap[last]
		m.heap = m.heap[:last]
		if i == last {
			return
		}
	}
	m.siftDown(i)
}

func (m *rollingPartMerge) next() *rollingPartCursor {
	switch {
	case !m.started:
		for i := len(m.heap)/2 - 1; i >= 0; i-- {
			m.siftDown(i)
		}
		m.started = true
	case m.baseWon:
		m.step(&m.base)
		m.hasBase = !m.base.exhausted()
	case len(m.heap) != 0:
		// Keep the previous winner untouched until the consumer is done.
		m.advance(0)
	}
	if len(m.heap) == 0 {
		m.baseWon = m.hasBase
		if m.hasBase {
			return &m.base
		}
		return nil
	}
	winner := &m.cursors[m.heap[0]]
	if m.hasBase {
		cmp := bytes.Compare(m.base.key, winner.key)
		if cmp < 0 {
			m.baseWon = true
			return &m.base
		}
		if cmp == 0 {
			m.shadow(&m.base)
			m.step(&m.base)
			m.hasBase = !m.base.exhausted()
		}
	}
	// A subtree can only contain another copy if its minimum is a copy.
	for i := 1; i <= 2; i++ {
		for i < len(m.heap) && bytes.Equal(winner.key, m.cursors[m.heap[i]].key) {
			m.shadow(&m.cursors[m.heap[i]])
			m.advance(i)
		}
	}
	m.baseWon = false
	return winner
}

func (r *Rolling) mergePart(m *rollingPartMerge, p rollingLookup) {
	m.reset()
	for _, o := range r.overlay[p.start:p.end] {
		m.add(r.segments[o.segment].run(int(o.run)), int(o.segment)+1)
	}
	if p.base >= 0 {
		m.base.rewind(r.base[p.base])
		m.step(&m.base)
		m.hasBase = !m.base.exhausted()
	}
}

// Diff compares a canonical, LF-delimited owner body with the effective
// snapshot. The input need not be sorted or unique.
func (f *RollingRefresh) Diff(ctx context.Context, owner string, body io.Reader) (_ *RollingChange, err error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	r := f.store
	idx := slices.Index(r.m.Owners, owner)
	if idx < 0 || len(r.catalog) == 0 || body == nil {
		return nil, errRolling
	}
	c := &RollingChange{owner: idx}
	defer func() {
		if err != nil {
			err = errors.Join(err, c.Close())
		}
	}()
	available := max(0, f.budget-f.retained)
	ends := r.rollingDiffEnds()
	c.ranges = make([]rollingKeySet, len(ends))
	type job struct {
		chunk        rollingKeySet
		merge        rollingPartMerge
		out          rollingCollector
		parts        []rollingLookup
		seen         []rollingSeen
		fullyScanned rollingSeen
		limit        int64
		unsorted     bool
		removes      int
	}
	jobs := make([]job, len(ends))
	defer func() {
		for i := range jobs {
			if z := &jobs[i].out; z.file != nil {
				err = errors.Join(err, z.file.Close())
			}
		}
	}()
	var scratchOnce sync.Once
	var scratchErr error
	scratch := func() (string, error) {
		scratchOnce.Do(func() { c.dir, scratchErr = os.MkdirTemp(r.dir, rollingDiffPrefix) })
		return c.dir, scratchErr
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var admitMu sync.Mutex
	admit := func(oldSize, newSize uint64) error {
		admitMu.Lock()
		defer admitMu.Unlock()
		if err := context.Cause(ctx); err != nil {
			return err
		}
		if f.admitWrite != nil {
			if err := f.admitWrite(oldSize, newSize); err != nil {
				cancel(err)
				return err
			}
		}
		return nil
	}
	var bitmapBytes int64
	lo := 0
	for i, end := range ends {
		hi := lo + sort.Search(len(r.parts)-lo, func(j int) bool { return int(r.parts[lo+j].id) >= end })
		j := &jobs[i]
		j.parts = r.parts[lo:hi]
		lo = hi
		j.seen = r.diffSeen(j.parts, &bitmapBytes)
		j.fullyScanned.bits = make([]byte, (len(j.parts)+7)/8)
		bitmapBytes += int64(len(j.fullyScanned.bits))
		j.out = rollingCollector{keys: &c.ranges[i], scratch: scratch, tag: fmt.Sprintf("out-%d", i), admitWrite: admit}
	}
	budget := min(max(0, available-bitmapBytes)/int64(len(jobs)), int64(int(^uint(0)>>1))/2)
	if budget >= 32<<10 {
		budget -= min(budget/3, r.diffScratchBudget())
	}
	for i := range jobs {
		j := &jobs[i]
		// Preserve room for the change set even while the next chunk is
		// being read. At tiny budgets give most of the space to changes.
		if budget < 4<<10 {
			j.out.budget = budget - budget/8
		} else {
			j.out.budget = budget / 4
		}
		j.limit = budget - j.out.budget
		if budget >= 1<<20 {
			// Keep capacity out of the reusable input buffers for
			// collected changes and transient allocations during growth.
			j.limit = min(j.limit-budget/8, rollingDiffChunkMax/int64(len(jobs)))
		}
	}
	parallel := func(active func(int) bool, work func(int) error) error {
		var wg sync.WaitGroup
		run := func(i int) {
			if context.Cause(ctx) == nil {
				if e := work(i); e != nil {
					cancel(e)
				}
			}
		}
		first := -1
		for i := range jobs {
			if active != nil && !active(i) {
				continue
			}
			if first < 0 {
				first = i
			} else {
				wg.Go(func() { run(i) })
			}
		}
		if first >= 0 {
			run(first)
		}
		wg.Wait()
		return context.Cause(ctx)
	}
	bit := uint64(1) << idx
	chunked := false
	join := func(final bool) error {
		return parallel(func(i int) bool { return final || len(jobs[i].chunk.spans) != 0 }, func(i int) error {
			j := &jobs[i]
			if j.unsorted {
				j.chunk.sortChunk()
			}
			remove := func(key []byte) error {
				j.removes++
				return j.out.add(key)
			}
			if err := r.diffJoin(ctx, &j.merge, j.parts, &j.chunk, bit, j.seen, &j.fullyScanned, final && !chunked, j.out.add, remove); err != nil {
				return err
			}
			if final {
				j.chunk = rollingKeySet{}
				// Its backing arrays may remain resident until a GC;
				// keep that capacity out of the collector's budget.
				if budget >= 1<<20 {
					j.out.budget = budget - j.limit - budget/8
				} else {
					j.out.budget = max(j.out.budget, budget)
				}
				if chunked {
					return r.diffRemoves(ctx, &j.merge, j.parts, bit, j.seen, &j.fullyScanned, remove)
				}
			} else {
				if j.chunk.retainedBytes() > j.limit {
					j.chunk = rollingKeySet{}
				} else {
					j.chunk.arena, j.chunk.spans = j.chunk.arena[:0], j.chunk.spans[:0]
				}
				j.unsorted = false
			}
			return nil
		})
	}
	bucket := 0
	scan := rollingScanner(body, 64<<10)
	for n := 0; scan.Scan(); n++ {
		if n&1023 == 0 && ctx.Err() != nil {
			return nil, context.Cause(ctx)
		}
		key := scan.Bytes()
		if len(key) > MaxKey {
			return nil, fmt.Errorf("%w: key too long", errRolling)
		}
		if len(ends) > 1 {
			id := int(psnID(key))
			if id >= ends[bucket] || (bucket > 0 && id < ends[bucket-1]) {
				bucket = sort.SearchInts(ends, id+1)
			}
		}
		j := &jobs[bucket]
		for {
			unsorted := j.unsorted
			if !unsorted && len(j.chunk.spans) != 0 {
				s := j.chunk.spans[len(j.chunk.spans)-1]
				cmp := bytes.Compare(j.chunk.arena[s.start:s.end], key)
				if cmp == 0 {
					break
				}
				unsorted = cmp > 0
			}
			if j.chunk.appendChunk(key, j.limit) {
				j.unsorted = unsorted
				break
			}
			if err = join(false); err != nil {
				return nil, err
			}
			chunked = true
		}
		if j.chunk.retainedBytes() > j.limit {
			if err = join(false); err != nil {
				return nil, err
			}
			chunked = true
		}
	}
	if err = scan.Err(); err != nil {
		return nil, err
	}
	if err = join(true); err != nil {
		return nil, err
	}
	err = parallel(nil, func(i int) error {
		j := &jobs[i]
		return j.out.finish(ctx)
	})
	if err != nil {
		return nil, err
	}
	for i := range jobs {
		j := &jobs[i]
		c.Adds += j.out.count - j.removes
		c.Removes += j.removes
	}
	c.refresh = f
	f.retained += c.retainedBytes()
	return c, nil
}

func (r *Rolling) diffScratchBudget() int64 {
	maxRuns := uint32(0)
	for _, p := range r.parts {
		maxRuns = max(maxRuns, p.end-p.start)
	}
	// Allow for one base cursor, the scanner, and spill I/O. Very small
	// budgets reserve a fraction instead of assuming every key is maximal.
	return (int64(maxRuns)+2)*(MaxKey+256) + 16<<10
}

// Split by record volume, including older versions that the merge visits.
func (r *Rolling) rollingDiffEnds() []int {
	workers := rollingWorkers()
	ends := make([]int, 0, workers)
	weight := func(p rollingLookup) int64 {
		var n int64
		if p.base >= 0 {
			n = int64(r.base[p.base].part.count)
		}
		for _, o := range r.overlay[p.start:p.end] {
			n += int64(r.segments[o.segment].count(int(o.run)))
		}
		return n
	}
	if workers > 1 && len(r.parts) > 0 {
		var total int64
		for _, p := range r.parts {
			total += weight(p)
		}
		var seen int64
		for i, p := range r.parts[:len(r.parts)-1] {
			seen += weight(p)
			if 2*seen >= total {
				ends = append(ends, int(r.parts[i+1].id))
				break
			}
		}
	}
	return append(ends, rollingIDs)
}

func (r *Rolling) diffSeen(parts []rollingLookup, charge *int64) []rollingSeen {
	seen := make([]rollingSeen, len(r.segments)+1)
	add := func(source int, run rollingRun) {
		p := &seen[source]
		if p.end == 0 {
			p.start = run.index
		}
		p.end = run.index + int(run.part.count)
	}
	for _, p := range parts {
		if p.base >= 0 {
			add(0, r.base[p.base])
		}
		for _, o := range r.overlay[p.start:p.end] {
			add(int(o.segment)+1, r.segments[o.segment].run(int(o.run)))
		}
	}
	// Adjacent workers own distinct index windows, including their
	// partial boundary bytes, so marking needs no atomic operations.
	for i := range seen {
		p := &seen[i]
		n := p.end - p.start
		size := n/8 + (n%8+7)/8
		p.bits = make([]byte, size)
		*charge += int64(size)
	}
	return seen
}

// A whole body proves absence immediately. With chunks, seen tracks matches
// and records already ruled out; only after EOF can unseen live keys be removed.
func (r *Rolling) diffJoin(ctx context.Context, merge *rollingPartMerge, parts []rollingLookup, chunk *rollingKeySet, bit uint64, seen []rollingSeen, fullyScanned *rollingSeen, wholeBody bool, add, remove func([]byte) error) error {
	addKey := add
	var added int
	add = func(key []byte) error {
		added++
		if added&1023 == 0 && ctx.Err() != nil {
			return context.Cause(ctx)
		}
		return addKey(key)
	}
	it := rollingKeyReader{arena: chunk.arena, spans: chunk.spans}
	id := rollingIDs
	next := func() {
		it.advance()
		id = rollingIDs
		if it.valid {
			id = int(psnID(it.key))
		}
	}
	next()
	start := 0
	if !wholeBody {
		start = sort.Search(len(parts), func(i int) bool { return int(parts[i].id) >= id })
	}
	for i, p := range parts[start:] {
		i += start
		if !wholeBody && id == rollingIDs {
			break
		}
		if err := context.Cause(ctx); err != nil {
			return err
		}
		pid := int(p.id)
		for id < pid {
			if err := add(it.key); err != nil {
				return err
			}
			next()
		}
		if !wholeBody && id != pid {
			continue
		}
		// Once the partition is traversed, every shadowed index is marked.
		// A later chunk can still mark additional matching owner records.
		cover := !wholeBody && !fullyScanned.has(i)
		merge.shadowed = nil
		if cover {
			merge.shadowed = seen
		}
		r.mergePart(merge, p)
		v := merge.next()
		for n := 0; v != nil && (wholeBody || id == pid || (cover && it.valid)); n, v = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return context.Cause(ctx)
			}
			cmp := 1
			for id == pid {
				cmp = bytes.Compare(it.key, v.key)
				if cmp >= 0 {
					break
				}
				if err := add(it.key); err != nil {
					return err
				}
				next()
				cmp = 1
			}
			owned := v.run.mask(v.index, r.width)&bit != 0
			if !wholeBody && (!owned || cmp == 0) {
				seen[v.source].mark(v.run.index + v.index)
			}
			if cmp == 0 {
				if !owned {
					if err := add(it.key); err != nil {
						return err
					}
				}
				next()
			} else if wholeBody && owned {
				if err := remove(v.key); err != nil {
					return err
				}
			}
		}
		if cover && v == nil {
			fullyScanned.mark(i)
		}
	}
	for it.valid {
		if err := add(it.key); err != nil {
			return err
		}
		it.advance()
	}
	return nil
}

func (r *Rolling) diffRemoves(ctx context.Context, merge *rollingPartMerge, parts []rollingLookup, bit uint64, seen []rollingSeen, fullyScanned *rollingSeen, remove func([]byte) error) error {
	merge.shadowed = nil
	merge.unseenContext = ctx
	for i, p := range parts {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		// In a fully traversed partition, unseen records are already
		// effective. Skip blocks without candidates instead of decoding
		// every key and resolving its shadowed versions again.
		merge.unseen = nil
		if p.start == p.end || fullyScanned.has(i) {
			merge.unseen = seen
		}
		r.mergePart(merge, p)
		for n, v := 0, merge.next(); v != nil; n, v = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if v.run.mask(v.index, r.width)&bit != 0 && !seen[v.source].has(v.run.index+v.index) {
				if err := remove(v.key); err != nil {
					return err
				}
			}
		}
	}
	return context.Cause(ctx)
}

type rollingCollector struct {
	keys       *rollingKeySet
	scratch    func() (string, error)
	tag, dir   string
	unsorted   bool
	budget     int64
	runs       int
	count      int // records in the current run, or in the finished change set
	file       *os.File
	writer     *bufio.Writer
	last       []byte
	maxRecord  int
	admitWrite func(uint64, uint64) error
}

func (z *rollingCollector) add(key []byte) error {
	c := z.keys
	if !z.unsorted && len(c.spans) != 0 {
		s := c.spans[len(c.spans)-1]
		cmp := bytes.Compare(c.arena[s.start:s.end], key)
		if cmp == 0 {
			return nil
		}
		z.unsorted = cmp > 0
	}
	if c.required(key) > z.budget && len(c.spans) > 0 {
		if err := z.flush(); err != nil {
			return err
		}
	}
	c.appendKey(key, z.budget)
	if int64(len(key))+spanBytes > z.budget {
		return z.flush()
	}
	return nil
}

func (c *rollingKeySet) required(key []byte) int64 {
	return int64(max(cap(c.arena), len(c.arena)+len(key))) + spanBytes*int64(max(cap(c.spans), len(c.spans)+1))
}

func (c *rollingKeySet) appendChunk(key []byte, limit int64) bool {
	if len(c.arena)+len(key) <= cap(c.arena) && len(c.spans) < cap(c.spans) {
		c.appendKey(key, limit)
		return true
	}
	required := c.required(key)
	if limit < 256<<10 {
		// With a tiny limit even one record can be oversized.
		if required > limit && len(c.spans) != 0 {
			return false
		}
		c.appendKey(key, limit)
		return true
	}
	if c.retainedBytes() == limit {
		return false
	}
	if required > rollingDiffChunkSeed {
		// Size both arrays once using the first few KiB of keys as a
		// sample. Reuse them at their fixed capacity for all later
		// chunks, rather than leaving a chain of large old arrays to GC.
		n := int64(len(c.spans)) + 1
		size := int64(len(c.arena) + len(key))
		records := min(limit*n/(size+spanBytes*n), (limit-MaxKey)/spanBytes)
		arena := make([]byte, len(c.arena), limit-spanBytes*records)
		copy(arena, c.arena)
		spans := make([]span, len(c.spans), records)
		copy(spans, c.spans)
		c.arena, c.spans = arena, spans
	}
	c.appendKey(key, min(limit, rollingDiffChunkSeed))
	return true
}

func (c *rollingKeySet) appendKey(key []byte, limit int64) {
	if len(c.arena)+len(key) > cap(c.arena) || len(c.spans) == cap(c.spans) {
		c.grow(key, limit)
	}
	start := len(c.arena)
	c.arena = append(c.arena, key...)
	c.spans = append(c.spans, span{uint32(start), uint32(len(c.arena))}) //nolint:gosec // G115: arena length is capped by the refresh budget, at most MaxUint32.
}

func (c *rollingKeySet) grow(key []byte, limit int64) {
	budget := max(limit, c.required(key))
	grow := func(n int) int64 {
		if n >= 4<<10 {
			return int64(n) + int64(n)/2
		}
		return int64(n) + int64(n)/4
	}
	start := len(c.arena)
	n := start + len(key)
	if n > cap(c.arena) {
		limit := budget - spanBytes*int64(max(cap(c.spans), len(c.spans)+1))
		buf := make([]byte, start, min(grow(n), limit))
		copy(buf, c.arena)
		c.arena = buf
	}
	n = len(c.spans) + 1
	if n > cap(c.spans) {
		limit := (budget - int64(cap(c.arena))) / spanBytes
		buf := make([]span, n-1, min(grow(n), limit))
		copy(buf, c.spans)
		c.spans = buf
	}
}

func (c *rollingKeySet) sort() {
	c.sortSpans(c.spans)
	c.dedup()
}

func (c *rollingKeySet) sortSpans(spans []span) {
	slices.SortFunc(spans, func(a, b span) int { return bytes.Compare(c.arena[a.start:a.end], c.arena[b.start:b.end]) })
}

func (c *rollingKeySet) dedup() {
	c.spans = slices.CompactFunc(c.spans, func(a, b span) bool { return bytes.Equal(c.arena[a.start:a.end], c.arena[b.start:b.end]) })
}

func (c *rollingKeySet) sortChunk() {
	c.sortPrefix(c.spans, 0)
	c.dedup()
}

// Group large chunks by PSN partition prefix before comparison sorting.
// Short keys share the zero bucket with NUL bytes and are ordered by the
// full comparison within that bucket.
func (c *rollingKeySet) sortPrefix(spans []span, depth uint32) {
	if len(spans) < 4096 || depth == 2 {
		c.sortSpans(spans)
		return
	}
	prefix := func(s span) byte {
		if s.end-s.start <= depth {
			return 0
		}
		return c.arena[s.start+depth]
	}
	var next, end [256]int
	for _, s := range spans {
		end[prefix(s)]++
	}
	pos := 0
	for i, n := range end {
		next[i] = pos
		pos += n
		end[i] = pos
	}
	pos = 0
	for i, stop := range end {
		for next[i] < stop {
			at := next[i]
			id := prefix(spans[at])
			if int(id) == i {
				next[i]++
				continue
			}
			to := next[id]
			spans[at], spans[to] = spans[to], spans[at]
			next[id]++
		}
		c.sortPrefix(spans[pos:stop], depth+1)
		pos = stop
	}
}

func (z *rollingCollector) name(pass, run int) string {
	return filepath.Join(z.dir, fmt.Sprintf("%s-%d-%d", z.tag, pass, run))
}

func (z *rollingCollector) flush() (err error) {
	c := z.keys
	if z.dir == "" {
		z.dir, err = z.scratch()
		if err != nil {
			return err
		}
		// Permit one I/O buffer's worth of records once spilling has
		// started; a zero budget must not create one file per key.
		z.budget = max(z.budget, 4<<10)
	}
	if z.unsorted {
		c.sort()
	}
	if len(c.spans) == 0 {
		return nil
	}
	s := c.spans[0]
	cmp := 1
	if z.runs != 0 {
		cmp = bytes.Compare(c.arena[s.start:s.end], z.last)
	}
	if z.runs == 0 || cmp < 0 {
		if err = z.closeRun(); err != nil {
			return err
		}
		z.file, err = os.Create(z.name(0, z.runs))
		if err != nil {
			return err
		}
		if z.writer == nil {
			z.writer = bufio.NewWriterSize(io.Discard, 4<<10)
		}
		z.writer.Reset(admitRunWrites(z.file, z.admitWrite))
		z.runs++
		z.count = 0
	}
	spans := c.spans
	if cmp == 0 {
		spans = spans[1:]
	}
	z.count += len(spans)
	var header [4]byte
	for _, s := range spans {
		key := c.arena[s.start:s.end]
		z.maxRecord = max(z.maxRecord, len(key))
		if err = writeRecord(z.writer, key, &header); err != nil {
			return err
		}
	}
	s = c.spans[len(c.spans)-1]
	z.last = append(z.last[:0], c.arena[s.start:s.end]...)
	c.arena, c.spans = c.arena[:0], c.spans[:0]
	z.unsorted = false
	return nil
}

func (z *rollingCollector) closeRun() error {
	if z.file == nil {
		return nil
	}
	err := errors.Join(z.writer.Flush(), z.file.Close())
	z.file = nil
	return err
}

func (z *rollingCollector) finish(ctx context.Context) error {
	c := z.keys
	if z.runs == 0 {
		if z.unsorted {
			c.sort()
		}
		z.count = len(c.spans)
		return nil
	}
	if len(c.spans) != 0 {
		if err := z.flush(); err != nil {
			return err
		}
	}
	if err := z.closeRun(); err != nil {
		return err
	}
	z.writer, z.last = nil, nil
	c.arena, c.spans = nil, nil
	// Use small I/O blocks under pressure. Two readers and one writer
	// are the minimum working set for reducing a set of spill runs.
	bufSize := int(min(4<<10, max(256, z.budget/8)))
	keySize := max(256, 2*z.maxRecord)
	fan := int(min(fanIn, max(2, (z.budget-int64(bufSize))/int64(keySize+bufSize))))
	pass, _, count, err := reduceRuns(ctx, z.name, z.runs, 1, fan, bufSize, z.admitWrite)
	if err != nil {
		return err
	}
	if pass != 0 {
		z.count = count
	}
	c.path = z.name(pass, 0)
	return nil
}
