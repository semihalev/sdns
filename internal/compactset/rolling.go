// Package compactset stores exact, disk-backed blocklist names and ownership.
// It partitions sorted names into shards that store each record's shared prefix
// length and remaining bytes, with a full name at the start of each block.
//
// A catalog routes keys to base partitions. Lookup checks newer immutable
// segments first, ignoring any at or below the catalog slice's FoldedThrough.
// Segment records replace the whole owner mask; a zero mask is a tombstone.
// Owner bits have no precedence here: the blocklist interprets its api-remove bit.
package compactset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cespare/xxhash/v2"
)

const (
	rollingVersion           = 4
	rollingIDs               = 1 << 16
	rollingCatalogMagic      = "CMPRCAT4"
	rollingSegmentMagic      = "CMPRSEG2"
	rollingCatalogHeader     = 20
	rollingCatalogEntryBytes = 46
	rollingSegmentHeader     = 20
	rollingSegmentEntryBytes = 10
	rollingPartPrefix        = "rolling-part-"
	rollingMaskPrefix        = "rolling-mask-"
	rollingCatalogPrefix     = "rolling-catalog-"
	rollingSegmentPrefix     = "rolling-segment-"
	rollingBuildPrefix       = ".rolling-build-"
	rollingDiffPrefix        = ".rolling-diff-"
	rollingBinarySuffix      = ".bin"
	rollingPartSuffix        = ".psn"
)

const (
	rollingSlices     = 24
	maxRollingWorkers = 2
)

func rollingWorkers() int { return max(1, min(maxRollingWorkers, runtime.GOMAXPROCS(0)-1)) }

var (
	errRolling         = errors.New("compactset: invalid rolling store")
	errMmapUnsupported = errors.New("compactset: mmap unsupported on this platform")
)

// RollingOptions defines a store's directory and stable owner bit assignments.
// The caller may reserve an owner ID for operator-local names.
type RollingOptions struct {
	Dir    string
	Owners []string
	// AdmitWrite approves growth in a file's logical size before BuildRolling
	// writes it, allowing the caller to account for blocks allocated on disk.
	AdmitWrite func(oldSize, newSize uint64) error
}

// rollingFile identifies a digest-verified immutable file by basename.
type rollingFile struct {
	Name  string `json:"name"`
	XXH64 string `json:"xxh64"`
}

// rollingSlice identifies the base catalog for a contiguous partition range.
type rollingSlice struct {
	Start         uint32      `json:"start"`
	End           uint32      `json:"end"`
	FoldedThrough uint64      `json:"folded_through"`
	Catalog       rollingFile `json:"catalog"`
}

// rollingSegment identifies one immutable batch of refresh operations.
type rollingSegment struct {
	Sequence uint64 `json:"sequence"`
	Count    uint32 `json:"count"`
	rollingFile
}

// RollingManifest belongs in the caller's atomically published checkpoint.
type RollingManifest struct {
	Version  int              `json:"version"`
	Owners   []string         `json:"owners"`
	Slices   []rollingSlice   `json:"slices"`
	Cursor   int              `json:"cursor"`
	Sequence uint64           `json:"sequence"`
	Segments []rollingSegment `json:"segments"`
	Count    int              `json:"count"`
}

func (m RollingManifest) clone() RollingManifest {
	m.Owners, m.Slices, m.Segments = slices.Clone(m.Owners), slices.Clone(m.Slices), slices.Clone(m.Segments)
	return m
}

// CheckLayout verifies checkpoint metadata without opening any artifacts.
func (m *RollingManifest) CheckLayout() error {
	if m.Version != rollingVersion {
		return fmt.Errorf("%w: rolling format version %d, want %d; reinstall the rolling store", errRolling, m.Version, rollingVersion)
	}
	if len(m.Slices) != rollingSlices || m.Cursor < 0 || m.Cursor >= len(m.Slices) || m.Count < 0 {
		return errRolling
	}
	var end uint32
	low := m.Sequence
	catalogs := make(map[string]bool, len(m.Slices))
	for _, s := range m.Slices {
		if s.Start != end || s.End <= s.Start || s.End > rollingIDs || s.FoldedThrough > m.Sequence || catalogs[s.Catalog.Name] {
			return errRolling
		}
		catalogs[s.Catalog.Name] = true
		end = s.End
		low = min(low, s.FoldedThrough)
	}
	if end != rollingIDs || uint64(len(m.Segments)) != m.Sequence-low || len(m.Segments) >= len(m.Slices) {
		return errRolling
	}
	for i, s := range m.Segments {
		if s.Sequence != low+uint64(i)+1 {
			return errRolling
		}
	}
	return nil
}

// RecordCounts returns the live key count and all retained segment records,
// including tombstones and records already folded into some catalog slices.
func (m *RollingManifest) RecordCounts() (keys, retained uint64) {
	keys = uint64(max(0, m.Count))
	for _, s := range m.Segments {
		n := uint64(s.Count)
		if n > math.MaxUint64-retained {
			return keys, math.MaxUint64
		}
		retained += n
	}
	return keys, retained
}

// CountVerificationScratch estimates live decoded key buffers during a cold
// open. Each worker may keep one per nonempty segment and one for the base.
func (m *RollingManifest) CountVerificationScratch() uint64 {
	var segments uint64
	for _, s := range m.Segments {
		if s.Count != 0 {
			segments++
		}
	}
	if segments == 0 {
		return 0
	}
	return maxRollingWorkers * (segments + 1) * MaxKey
}

type rollingPartMeta struct {
	id                                        uint16
	count                                     uint32
	nonce                                     [16]byte
	keyDigest, partitionDigest, sidecarDigest uint64
}

func (p rollingPartMeta) names() (string, string) {
	return p.partName(), p.maskName()
}

func (p rollingPartMeta) partName() string {
	return fmt.Sprintf(rollingPartPrefix+"%04x-%x"+rollingPartSuffix, p.id, p.nonce)
}

func (p rollingPartMeta) maskName() string {
	return fmt.Sprintf(rollingMaskPrefix+"%04x-%x"+rollingBinarySuffix, p.id, p.nonce)
}

// IsArtifact reports whether name has the form of an immutable store file.
func IsArtifact(name string) bool {
	return rollingArtifactName(name, rollingCatalogPrefix, rollingBinarySuffix, false) ||
		rollingArtifactName(name, rollingSegmentPrefix, rollingBinarySuffix, false) ||
		rollingArtifactName(name, rollingMaskPrefix, rollingBinarySuffix, true) ||
		rollingArtifactName(name, rollingPartPrefix, rollingPartSuffix, true)
}

func rollingArtifactName(name, prefix, suffix string, partition bool) bool {
	token, ok := strings.CutPrefix(name, prefix)
	token, ext := strings.CutSuffix(token, suffix)
	if !ok || !ext {
		return false
	}
	if partition {
		if len(token) != 37 || token[4] != '-' || !rollingHex(token[:4]) {
			return false
		}
		token = token[5:]
	}
	return len(token) == 32 && rollingHex(token)
}

func rollingHex(token string) bool {
	for i := range len(token) {
		b := token[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

// IsScratchDir reports whether name has the form of a store scratch directory.
func IsScratchDir(name string) bool {
	token, ok := strings.CutPrefix(name, rollingBuildPrefix)
	if !ok {
		token, ok = strings.CutPrefix(name, rollingDiffPrefix)
	}
	if !ok || token == "" {
		return false
	}
	for i := range len(token) {
		if token[i] < '0' || token[i] > '9' {
			return false
		}
	}
	return true
}

func parseRollingPart(b []byte) (p rollingPartMeta) {
	p.id, p.count = le.Uint16(b), le.Uint32(b[2:])
	copy(p.nonce[:], b[6:22])
	p.keyDigest = le.Uint64(b[22:])
	p.partitionDigest = le.Uint64(b[30:])
	p.sidecarDigest = le.Uint64(b[38:])
	return p
}

func (p rollingPartMeta) encode(b []byte) {
	le.PutUint16(b, p.id)
	le.PutUint32(b[2:], p.count)
	copy(b[6:], p.nonce[:])
	le.PutUint64(b[22:], p.keyDigest)
	le.PutUint64(b[30:], p.partitionDigest)
	le.PutUint64(b[38:], p.sidecarDigest)
}

// Distinct views may release their references concurrently. Reopen must hold
// its predecessor open until it has acquired the references it needs.
type rollingMapping struct {
	refs          atomic.Int32
	data, sidecar []byte
}

func newRollingMapping(data []byte) *rollingMapping {
	mapping := &rollingMapping{data: data}
	mapping.refs.Store(1)
	return mapping
}

func (m *rollingMapping) retain() *rollingMapping {
	m.refs.Add(1)
	return m
}

func (m *rollingMapping) release() error {
	if m == nil || m.refs.Add(-1) != 0 {
		return nil
	}
	err := unmapFile(m.data)
	if m.sidecar != nil {
		err = errors.Join(err, unmapFile(m.sidecar))
	}
	return err
}

type rollingRun struct {
	part    psnPartition
	masks   []byte
	index   int
	mapping *rollingMapping
}

type rollingSegmentMap struct {
	data, filter []byte
	blocks, salt uint32
	parts, width int
	mapping      *rollingMapping
}

func (s rollingSegmentMap) entry(i int) []byte {
	return s.data[rollingSegmentHeader+i*rollingSegmentEntryBytes:][:rollingSegmentEntryBytes]
}

func (s rollingSegmentMap) count(i int) uint32 {
	return le.Uint32(s.entry(i + 1)[6:]) - le.Uint32(s.entry(i)[6:])
}

func (s rollingSegmentMap) run(i int) rollingRun {
	b, next := s.entry(i), s.entry(i+1)
	off, end := int(le.Uint32(b[2:])), int(le.Uint32(next[2:]))
	index := le.Uint32(b[6:])
	count := le.Uint32(next[6:]) - index
	maskStart := end - int(count)*s.width
	return rollingRun{part: psnPartition{id: le.Uint16(b), count: count, data: s.data[off:maskStart]}, masks: s.data[maskStart:end], index: int(index)}
}

func (s rollingSegmentMap) find(id uint16) int {
	i := sort.Search(s.parts, func(i int) bool { return le.Uint16(s.entry(i)) >= id })
	if i == s.parts || le.Uint16(s.entry(i)) != id {
		return -1
	}
	return i
}

// Rolling is an immutable, mmap-backed view. It may serve parallel
// readers; the owner must stop them before closing it. Apply stages a new
// snapshot without changing this view or publishing a manifest.
type Rolling struct {
	dir       string
	m         RollingManifest
	width     int
	catalog   []rollingCatalogMap
	base      []rollingRun
	baseCount int
	segments  []rollingSegmentMap
	parts     []rollingLookup
	overlay   []rollingOverlay
}

type rollingCatalogMap struct {
	mapping *rollingMapping
	first   int
	count   int
}

func (c rollingCatalogMap) entry(i int) rollingPartMeta {
	return parseRollingPart(c.mapping.data[rollingCatalogHeader+i*rollingCatalogEntryBytes:][:rollingCatalogEntryBytes])
}

type rollingLookup struct {
	id         uint16
	base       int32
	start, end uint32
}

type rollingOverlay struct {
	segment, run uint16
}

func rollingOwners(owners []string) (int, error) {
	if len(owners) < 1 || len(owners) > 64 {
		return 0, fmt.Errorf("%w: expected 1–64 owners", errRolling)
	}
	for i, id := range owners {
		if id == "" || slices.Contains(owners[:i], id) {
			return 0, fmt.Errorf("%w: empty or duplicate owner ID", errRolling)
		}
	}
	switch {
	case len(owners) <= 8:
		return 1, nil
	case len(owners) <= 16:
		return 2, nil
	case len(owners) <= 32:
		return 4, nil
	default:
		return 8, nil
	}
}

func rollingMask(b []byte, width int) uint64 {
	switch width {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(le.Uint16(b))
	case 4:
		return uint64(le.Uint32(b))
	default:
		return le.Uint64(b)
	}
}

func (p *rollingRun) mask(i, width int) uint64 { return rollingMask(p.masks[i*width:], width) }

func rollingMapFile(ctx context.Context, path string, minimum int64, want uint64) ([]byte, error) {
	f, err := openRollingArtifact(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: artifact %s is not a regular file", errRolling, filepath.Base(path))
	}
	if st.Size() < minimum || st.Size() > int64(psnMaxShardLength) {
		return nil, fmt.Errorf("%w: artifact %s has invalid size %d bytes", errRolling, filepath.Base(path), st.Size())
	}
	data, err := mapFile(f, int(st.Size()))
	if err != nil {
		return nil, err
	}
	sum, err := rollingDigest(ctx, data)
	if err != nil || sum != want {
		_ = unmapFile(data)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: digest mismatch for %s", errRolling, filepath.Base(path))
	}
	return data, nil
}

func rollingMapReference(ctx context.Context, dir, prefix string, ref rollingFile) ([]byte, error) {
	if !rollingArtifactName(ref.Name, prefix, rollingBinarySuffix, false) {
		return nil, errRolling
	}
	want, err := strconv.ParseUint(ref.XXH64, 16, 64)
	if err != nil || len(ref.XXH64) != 16 {
		return nil, errRolling
	}
	return rollingMapFile(ctx, filepath.Join(dir, ref.Name), 1, want)
}

func rollingDigest(ctx context.Context, data []byte) (uint64, error) {
	const chunk = 1 << 20
	if err := context.Cause(ctx); err != nil {
		return 0, err
	}
	if len(data) <= chunk {
		return xxhash.Sum64(data), nil
	}
	h := xxhash.New()
	for len(data) != 0 {
		if err := context.Cause(ctx); err != nil {
			return 0, err
		}
		n := min(chunk, len(data))
		_, _ = h.Write(data[:n])
		data = data[n:]
	}
	return h.Sum64(), nil
}

// OpenRolling verifies all mapped files eagerly. Data is never replayed into
// decoded heap storage; only the sparse partition/segment routing index is.
func OpenRolling(ctx context.Context, opt RollingOptions, m RollingManifest) (*Rolling, error) {
	return openRolling(ctx, opt.Dir, opt.Owners, m, nil, false)
}

// Reopen derives a new view while the receiver remains open. Published files
// must remain immutable: they are verified when first mapped and reused by
// name and digest across views. OpenRolling at startup verifies everything.
func (r *Rolling) Reopen(ctx context.Context, m RollingManifest) (*Rolling, error) {
	if len(r.catalog) == 0 {
		return nil, errRolling
	}
	return openRolling(ctx, r.dir, r.m.Owners, m, r, false)
}

// privateManifest permits borrowing the manifest's slices and skipping the
// recount: the manifest is the private result of applying the changes.
func openRolling(ctx context.Context, dir string, owners []string, m RollingManifest, previous *Rolling, privateManifest bool) (_ *Rolling, err error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	width, err := rollingOwners(owners)
	if err != nil {
		return nil, err
	}
	if err = m.CheckLayout(); err != nil {
		return nil, err
	}
	if !slices.Equal(owners, m.Owners) {
		return nil, errRolling
	}
	if !privateManifest {
		m = m.clone()
	}
	r := &Rolling{dir: dir, m: m, width: width}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	var oldCatalogs, oldSegments map[rollingFile]int
	if previous != nil {
		oldCatalogs = make(map[rollingFile]int, len(previous.catalog))
		for i, s := range previous.m.Slices {
			oldCatalogs[s.Catalog] = i
		}
		oldSegments = make(map[rollingFile]int, len(previous.segments))
		for i, s := range previous.m.Segments {
			oldSegments[s.rollingFile] = i
		}
	}
	r.catalog = make([]rollingCatalogMap, 0, len(m.Slices))
	var total int
	for _, s := range m.Slices {
		if i, ok := oldCatalogs[s.Catalog]; ok {
			old := previous.m.Slices[i]
			if old.Start != s.Start || old.End != s.End {
				return nil, fmt.Errorf("%w: invalid catalog header for slice [%d,%d)", errRolling, s.Start, s.End)
			}
			c := previous.catalog[i]
			r.catalog = append(r.catalog, rollingCatalogMap{mapping: c.mapping.retain(), first: total, count: c.count})
			total += c.count
			continue
		}
		data, openErr := rollingMapReference(ctx, dir, rollingCatalogPrefix, s.Catalog)
		if openErr != nil {
			return nil, openErr
		}
		mapping := newRollingMapping(data)
		r.catalog = append(r.catalog, rollingCatalogMap{mapping: mapping, first: total})
		if len(data) < rollingCatalogHeader || string(data[:8]) != rollingCatalogMagic ||
			le.Uint32(data[12:]) != s.Start || le.Uint32(data[16:]) != s.End {
			return nil, fmt.Errorf("%w: invalid catalog header for slice [%d,%d)", errRolling, s.Start, s.End)
		}
		n := le.Uint32(data[8:])
		if n > s.End-s.Start || len(data) != rollingCatalogHeader+int(n)*rollingCatalogEntryBytes {
			return nil, errRolling
		}
		r.catalog[len(r.catalog)-1].count = int(n)
		total += int(n)
	}
	r.base = make([]rollingRun, 0, total)
	var oldPart, oldSlice int
	for i, c := range r.catalog {
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		s := m.Slices[i]
		if i, ok := oldCatalogs[s.Catalog]; ok {
			c := previous.catalog[i]
			oldSlice, oldPart = i, c.first+c.count
			for j := c.first; j < oldPart; j++ {
				run := &previous.base[j]
				if int(run.part.count) > int(^uint(0)>>1)-r.baseCount {
					return nil, errRolling
				}
				r.base = append(r.base, rollingRun{part: run.part, masks: run.masks, index: r.baseCount,
					mapping: run.mapping.retain()})
				r.baseCount += int(run.part.count)
			}
			continue
		}
		var last uint16
		for j := range c.count {
			p := c.entry(j)
			if p.count == 0 || uint32(p.id) < s.Start || uint32(p.id) >= s.End || (j > 0 && p.id <= last) {
				return nil, errRolling
			}
			last = p.id
			var old *rollingRun
			var oldMeta rollingPartMeta
			if previous != nil {
				for oldPart < len(previous.base) && previous.base[oldPart].part.id < p.id {
					oldPart++
				}
				if oldPart < len(previous.base) && previous.base[oldPart].part.id == p.id {
					for uint32(p.id) >= previous.m.Slices[oldSlice].End {
						oldSlice++
					}
					c := previous.catalog[oldSlice]
					old, oldMeta = &previous.base[oldPart], c.entry(oldPart-c.first)
				}
			}
			if err = r.openBasePart(ctx, p, old, oldMeta); err != nil {
				return nil, err
			}
		}
	}
	r.segments = make([]rollingSegmentMap, 0, len(m.Segments))
	for _, s := range m.Segments {
		if i, ok := oldSegments[s.rollingFile]; ok {
			if previous.m.Segments[i].Count != s.Count {
				return nil, fmt.Errorf("rolling segment %s: %w", s.Name, errRolling)
			}
			segment := previous.segments[i]
			segment.mapping.retain()
			r.segments = append(r.segments, segment)
			continue
		}
		data, openErr := rollingMapReference(ctx, dir, rollingSegmentPrefix, s.rollingFile)
		if openErr != nil {
			return nil, openErr
		}
		r.segments = append(r.segments, rollingSegmentMap{data: data, width: width, mapping: newRollingMapping(data)})
		if err = r.segments[len(r.segments)-1].validate(ctx, s.Count, len(m.Owners)); err != nil {
			return nil, fmt.Errorf("rolling segment %s: %w", s.Name, err)
		}
	}
	if err = r.index(ctx); err != nil {
		return nil, err
	}
	if !privateManifest {
		count := r.unionCount(ctx)
		if err := context.Cause(ctx); err != nil {
			return nil, err
		}
		if count != int64(m.Count) {
			return nil, fmt.Errorf("%w: manifest count %d, found %d", errRolling, m.Count, count)
		}
	}
	return r, nil
}

func (r *Rolling) openBasePart(ctx context.Context, p rollingPartMeta, old *rollingRun, oldMeta rollingPartMeta) error {
	if err := context.Cause(ctx); err != nil {
		return err
	}
	if uint64(p.count) > uint64(int(^uint(0)>>1)-r.baseCount) { //nolint:gosec // G115: baseCount is checked against MaxInt before each increment.
		return errRolling
	}
	r.base = append(r.base, rollingRun{index: r.baseCount})
	run := &r.base[len(r.base)-1]
	if old != nil && p == oldMeta {
		run.part, run.masks, run.mapping = old.part, old.masks, old.mapping.retain()
		r.baseCount += int(p.count)
		return nil
	}
	partName := p.partName()
	data, err := rollingMapFile(ctx, filepath.Join(r.dir, partName), psnMinSize(p.count), p.partitionDigest)
	if err != nil {
		return fmt.Errorf("rolling partition %s: %w", partName, err)
	}
	run.part = psnPartition{id: p.id, count: p.count, data: data}
	run.mapping = newRollingMapping(data)
	digest, err := run.part.checkedKeysDigest(ctx)
	if err != nil {
		return fmt.Errorf("rolling partition %s: %w", partName, err)
	}
	if digest != p.keyDigest {
		return fmt.Errorf("%w: key digest mismatch for %s", errRolling, partName)
	}
	maskName := p.maskName()
	masks, err := rollingMapFile(ctx, filepath.Join(r.dir, maskName), 1, p.sidecarDigest)
	if err != nil {
		return err
	}
	run.masks, run.mapping.sidecar = masks, masks
	if uint64(len(masks)) != uint64(p.count)*uint64(r.width) { //nolint:gosec // G115: width is 1, 2, 4, or 8.
		return fmt.Errorf("%w: invalid sidecar %s", errRolling, maskName)
	}
	for j := range int(p.count) {
		if j&1023 == 0 && ctx.Err() != nil {
			return context.Cause(ctx)
		}
		mask := run.mask(j, r.width)
		if mask == 0 || mask>>len(r.m.Owners) != 0 {
			return errRolling
		}
	}
	r.baseCount += int(p.count)
	return nil
}

func (s *rollingSegmentMap) validate(ctx context.Context, count uint32, owners int) error {
	if len(s.data) < rollingSegmentHeader || string(s.data[:8]) != rollingSegmentMagic {
		return errRolling
	}
	parts := le.Uint32(s.data[8:])
	s.blocks, s.salt = le.Uint32(s.data[12:]), le.Uint32(s.data[16:])
	s.parts = int(parts)
	if parts > rollingIDs || s.blocks > rollingFilterBlocks(count) || (s.blocks == 0) != (count == 0) {
		return errRolling
	}
	start := uint64(rollingSegmentHeader) + (uint64(parts)+1)*rollingSegmentEntryBytes
	filterSize := uint64(s.blocks) * 8
	if start+filterSize > uint64(len(s.data)) {
		return errRolling
	}
	end := uint64(len(s.data)) - filterSize
	s.filter = s.data[end:]
	first, sentinel := s.entry(0), s.entry(s.parts)
	if le.Uint32(first[6:]) != 0 || uint64(le.Uint32(first[2:])) != start ||
		le.Uint16(sentinel) != 0 || le.Uint32(sentinel[6:]) != count || uint64(le.Uint32(sentinel[2:])) != end {
		return errRolling
	}
	var last uint16
	var keys psnKeyValidator
	for i := range s.parts {
		b, next := s.entry(i), s.entry(i+1)
		id := le.Uint16(b)
		off, limit := uint64(le.Uint32(b[2:])), uint64(le.Uint32(next[2:]))
		index, nextIndex := le.Uint32(b[6:]), le.Uint32(next[6:])
		if (i > 0 && id <= last) || nextIndex <= index || nextIndex > count || limit <= off || limit > end {
			return errRolling
		}
		n := nextIndex - index
		if limit-off < uint64(psnMinSize(n))+uint64(n)*uint64(s.width) { //nolint:gosec // G115: block count and mask width are nonnegative.
			return errRolling
		}
		last = id
		run := s.run(i)
		if le.Uint32(run.part.data) != n {
			return errRolling
		}
		keys.start(n)
		for j := range n {
			if j&1023 == 0 && ctx.Err() != nil {
				return context.Cause(ctx)
			}
			key := keys.next(&run.part, j)
			if key == nil || run.mask(int(j), s.width)>>owners != 0 {
				return errRolling
			}
			h := xxhash.Sum64(key)
			if !s.mayContain(uint32(h>>32), rollingFilterBits(h)) {
				return errRolling
			}
		}
		if keys.pos != len(run.part.data) {
			return errRolling
		}
	}
	return nil
}

func (r *Rolling) sliceFor(id uint16) int {
	return sort.Search(len(r.m.Slices), func(i int) bool { return r.m.Slices[i].End > uint32(id) })
}

func (r *Rolling) index(ctx context.Context) error {
	var ids [rollingIDs / 64]uint64
	for _, p := range r.base {
		ids[p.part.id/64] |= 1 << (p.part.id % 64)
	}
	for _, s := range r.segments {
		for j := range s.parts {
			id := le.Uint16(s.entry(j))
			ids[id/64] |= 1 << (id % 64)
		}
	}
	base := 0
	for i := range rollingIDs {
		if i&1023 == 0 && ctx.Err() != nil {
			return context.Cause(ctx)
		}
		if ids[i/64]&(1<<(i%64)) == 0 {
			continue
		}
		id := uint16(i)
		p := rollingLookup{id: id, base: -1, start: uint32(len(r.overlay))} //nolint:gosec // G115: at most one entry per partition per retained segment.
		if base < len(r.base) && r.base[base].part.id == id {
			p.base = int32(base)
			base++
		}
		through := r.m.Slices[r.sliceFor(id)].FoldedThrough
		for j := len(r.segments) - 1; j >= 0 && r.m.Segments[j].Sequence > through; j-- {
			if k := r.segments[j].find(id); k >= 0 {
				r.overlay = append(r.overlay, rollingOverlay{uint16(j), uint16(k)}) //nolint:gosec // G115: fewer than 24 segments, at most 65536 partitions in each.
			}
		}
		p.end = uint32(len(r.overlay)) //nolint:gosec // G115: at most one entry per partition per retained segment.
		if p.base >= 0 || p.start != p.end {
			r.parts = append(r.parts, p)
		}
	}
	return context.Cause(ctx)
}

func (r *Rolling) unionCount(ctx context.Context) int64 {
	count := int64(r.baseCount)
	if len(r.overlay) == 0 {
		return count
	}
	// For a large live overlay, count disjoint ranges at the same balanced
	// slice boundaries used for folding. Small checkpoints stay serial.
	workers := min(rollingWorkers(), 1+len(r.overlay)/1024)
	if workers == 1 {
		return count + r.overlayDelta(ctx, r.parts)
	}
	var group sync.WaitGroup
	var deltas [maxRollingWorkers]int64
	start := 0
	for i := range workers - 1 {
		boundary := r.m.Slices[(i+1)*len(r.m.Slices)/workers].Start
		end := start + sort.Search(len(r.parts)-start, func(j int) bool {
			return uint32(r.parts[start+j].id) >= boundary
		})
		parts := r.parts[start:end]
		group.Go(func() { deltas[i] = r.overlayDelta(ctx, parts) })
		start = end
	}
	count += r.overlayDelta(ctx, r.parts[start:])
	group.Wait()
	for _, delta := range deltas[:workers-1] {
		count += delta
	}
	return count
}

func (r *Rolling) overlayDelta(ctx context.Context, parts []rollingLookup) int64 {
	var delta int64
	// The index excludes folded records. Merge the live overlay for each
	// partition, and intersect it with the sorted base a block at a time.
	var merge rollingPartMerge
	var base rollingPartCursor
	for _, p := range parts {
		if ctx.Err() != nil {
			return 0
		}
		if p.start == p.end {
			continue
		}
		hasBase := p.base >= 0
		if hasBase {
			base.rewind(r.base[p.base])
			p.base = -1
		}
		r.mergePart(&merge, p)
		for n, entry := 0, merge.next(); entry != nil; n, entry = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return 0
			}
			live := entry.run.mask(entry.index, r.width) != 0
			inBase := hasBase && base.seek(entry.key)
			switch {
			case live && !inBase:
				delta++
			case !live && inBase:
				delta--
			}
		}
	}
	return delta
}

func rollingFindInPart(part *psnPartition, key []byte) int {
	block := sort.Search(psnBlockCount(part.count), func(i int) bool {
		return bytes.Compare(part.firstInBlock(i), key) > 0
	}) - 1
	if block < 0 {
		return -1
	}
	i := part.findInBlock(block, key)
	if i < 0 {
		return -1
	}
	return block*psnBlock + i
}

// IterateOwner visits the canonical keys owned by one source in the live view.
// Each key is borrowed, read-only, and valid only until visit returns.
func (r *Rolling) IterateOwner(ctx context.Context, owner string, visit func([]byte) error) error {
	i := slices.Index(r.m.Owners, owner)
	if i < 0 {
		return fmt.Errorf("%w: unknown owner %q", errRolling, owner)
	}
	mask := uint64(1) << i
	var merge rollingPartMerge
	for _, part := range r.parts {
		if err := context.Cause(ctx); err != nil {
			return err
		}
		r.mergePart(&merge, part)
		for n, key := 0, merge.next(); key != nil; n, key = n+1, merge.next() {
			if n&1023 == 0 && ctx.Err() != nil {
				return context.Cause(ctx)
			}
			if key.run.mask(key.index, r.width)&mask != 0 {
				if err := visit(key.key); err != nil {
					return err
				}
			}
		}
	}
	return context.Cause(ctx)
}

// OwnerMask reports which owners, in RollingOptions.Owners order, list key in
// the live view. The exact lookup does not allocate or normalize the key.
func (r *Rolling) OwnerMask(key []byte) uint64 {
	if len(key) > MaxKey {
		return 0
	}
	id := psnID(key)
	i := sort.Search(len(r.parts), func(i int) bool { return r.parts[i].id >= id })
	if i == len(r.parts) || r.parts[i].id != id {
		return 0
	}
	p := r.parts[i]
	if p.start != p.end {
		h := xxhash.Sum64(key)
		blockHash, bits := uint32(h>>32), rollingFilterBits(h)
		for _, o := range r.overlay[p.start:p.end] {
			s := &r.segments[o.segment]
			if !s.mayContain(blockHash, bits) {
				continue
			}
			run := s.run(int(o.run))
			if index := rollingFindInPart(&run.part, key); index >= 0 {
				return run.mask(index, r.width)
			}
		}
	}
	if p.base >= 0 {
		run := &r.base[p.base]
		if index := rollingFindInPart(&run.part, key); index >= 0 {
			return run.mask(index, r.width)
		}
	}
	return 0
}

// Files marks basenames needed by this snapshot. Physical deletion belongs to
// the caller after a successful manifest switch and release of older readers.
func (r *Rolling) Files(keep map[string]bool) {
	for i, c := range r.catalog {
		keep[r.m.Slices[i].Catalog.Name] = true
		for j := range c.count {
			p, m := c.entry(j).names()
			keep[p], keep[m] = true, true
		}
	}
	for _, s := range r.m.Segments {
		keep[s.Name] = true
	}
}

// Close releases this view's mappings after its readers have exited.
func (r *Rolling) Close() (err error) {
	for i := range r.base {
		p := &r.base[i]
		err = errors.Join(err, p.mapping.release())
	}
	for _, s := range r.segments {
		err = errors.Join(err, s.mapping.release())
	}
	for _, c := range r.catalog {
		err = errors.Join(err, c.mapping.release())
	}
	r.base, r.segments, r.catalog, r.overlay, r.parts = nil, nil, nil, nil, nil
	return err
}

// One 64-bit Bloom word per eight keys. Split the word into four lanes so
// the same key never picks the same bit twice, even with a tiny filter.
func rollingFilterBlocks(count uint32) uint32 { return count/8 + (count%8+7)/8 }

func rollingFilterBits(h uint64) uint64 {
	return 1<<(h&15) | 1<<(16+(h>>4&15)) | 1<<(32+(h>>8&15)) | 1<<(48+(h>>12&15))
}

func rollingFilterOffset(hash, salt, blocks uint32) int {
	return int(uint64(hash+salt)*uint64(blocks)>>32) * 8
}

func (s *rollingSegmentMap) mayContain(hash uint32, bits uint64) bool {
	off := rollingFilterOffset(hash, s.salt, s.blocks)
	return le.Uint64(s.filter[off:])&bits == bits
}
