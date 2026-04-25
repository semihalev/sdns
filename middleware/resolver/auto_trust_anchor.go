package resolver

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/util"
	"github.com/semihalev/zlog/v2"
)

// errCorruptTombstones is returned by readTombstones when the file
// exists, was successfully opened, but its bytes don't decode as a
// gob-encoded Tombstones map. Distinct from open errors (e.g. a
// Windows sharing violation while a concurrent writer is mid-
// rename), which are transient and should not be treated as
// corruption.
var errCorruptTombstones = errors.New("trust anchor tombstones file corrupt")

// State represents the state of a trust anchor in RFC 5011 lifecycle.
type State int

const (
	StateStart State = iota
	StateAddPend
	StateValid
	StateMissing
	StateRevoked
	StateRemoved
)

const (
	DNSKEYFlagKSK    = 0x0001
	DNSKEYFlagRevoke = 0x0080
)

const (
	stateFile     = "trust-anchor.db"
	tombstoneFile = "trust-anchor-tombstones.db"
)

// TrustAnchor holds a DNSSEC trust anchor with its state and metadata.
type TrustAnchor struct {
	DNSKey    *dns.DNSKEY
	State     State
	FirstSeen time.Time
}

// TrustAnchors maps key tags to their trust anchor data.
type TrustAnchors map[uint16]*TrustAnchor

// Tombstone records a DNSKEY whose revocation we have observed. Per
// RFC 5011 §2.1 revocation is "immediate and permanent", so these
// entries live forever.
type Tombstone struct {
	DNSKey    *dns.DNSKEY
	FirstSeen time.Time
}

// Tombstones are keyed by DNSKEY material fingerprint — never by key
// tag. Tag-keyed storage would let a future KSK with a colliding
// 16-bit tag suppress itself against an unrelated tombstone.
type Tombstones map[string]*Tombstone

// dnskeyMaterialFP is a stable identifier for a DNSKEY's cryptographic
// material: algorithm, protocol, and public key bits. It intentionally
// excludes Flags so a key's tombstone matches both its revoked and
// un-revoked forms.
func dnskeyMaterialFP(k *dns.DNSKEY) string {
	if k == nil {
		return ""
	}
	return fmt.Sprintf("%d|%d|%s", k.Algorithm, k.Protocol, k.PublicKey)
}

func (s State) String() string {
	switch s {
	case StateStart:
		return "START"
	case StateAddPend:
		return "PENDING"
	case StateValid:
		return "VALID"
	case StateMissing:
		return "MISSING"
	case StateRevoked:
		return "REVOKED"
	case StateRemoved:
		return "REMOVED"
	default:
		return ""
	}
}

func (r *Resolver) AutoTA() {
	filename := filepath.Join(r.cfg.Directory, stateFile)
	tombstonePath := filepath.Join(r.cfg.Directory, tombstoneFile)

	// Snapshot whether the live trust set was non-empty when this
	// run started. A nil/empty r.rootKeys signals that a prior run
	// hit a persistence failure and put us in fail-closed mode; we
	// must not republish from disk in that case because disk could
	// still carry the un-revoked anchor whose revocation we already
	// observed in memory. A non-empty value means either the
	// initial config seed or a previous successful AutoTA — both
	// are safe upper bounds, so a tombstone-filtered subset of disk
	// state is at least as restrictive and may safely be published
	// before the external fetch.
	priorTrustValid := r.hasTrustAnchors()

	// Track whether this run produced a fresh contraction event —
	// a brand-new revocation that exists only in memory until the
	// writes land. Only that case requires fail-closed handling on
	// dual-write failure; an unrelated refresh that happens to
	// race a read-only/full disk shouldn't tear down working trust
	// anchors. Pre-existing StateRevoked entries (legacy migration)
	// are already durable in the state file, so they don't count.
	newRevocation := false

	kskCurrent, err := readFromTAFile(filename)
	if err != nil {
		zlog.Warn("No trust anchor state file found or the state corrupted! New one will be generate.", "path", filename)

		kskCurrent = make(TrustAnchors)

		for _, rr := range r.rootKeys {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				if dnskey.Flags&DNSKEYFlagKSK != 0 {
					keyTag := dnskey.KeyTag()
					ta := &TrustAnchor{
						DNSKey:    dnskey,
						State:     StateValid,
						FirstSeen: time.Now(),
					}

					if dnskey.Flags&DNSKEYFlagRevoke != 0 {
						ta.State = StateRevoked
					}

					kskCurrent[keyTag] = ta
				}
			}
		}
	}

	tombstones, err := readTombstones(tombstonePath)
	if err != nil {
		// Distinguish "transient inability to read" from "actual
		// corruption". A sharing violation on Windows (concurrent
		// writer renaming over the file) or a permission hiccup is
		// not the same as a malformed gob payload. We only fail
		// closed when we successfully read bytes that don't decode
		// — readTombstones surfaces that as errCorruptTombstones.
		// Other open errors leave us with an empty in-memory map
		// and the next AutoTA tick (or a process restart in the
		// non-transient case) can re-load.
		if errors.Is(err, errCorruptTombstones) {
			zlog.Error("Trust anchor tombstones file corrupted — clearing in-memory trust set and aborting refresh", "path", tombstonePath, "error", err.Error())
			r.Lock()
			r.rootKeys = nil
			r.Unlock()
			return
		}
		zlog.Warn("Trust anchor tombstones file unreadable — proceeding with empty in-memory tombstones", "path", tombstonePath, "error", err.Error())
		tombstones = make(Tombstones)
	}

	// Copy legacy Revoked/Removed entries into the material-keyed
	// tombstone store so tag collisions with a future legitimate KSK
	// can't suppress that future key. Keep the markers in kskCurrent
	// for now: if writeTombstones fails this run, the StateRevoked
	// marker in the main state file is the only durable record of
	// the revocation, and the post-write cleanup below only deletes
	// them after tombstones are durably written.
	for _, ta := range kskCurrent {
		if ta.State == StateRevoked || ta.State == StateRemoved {
			fp := dnskeyMaterialFP(ta.DNSKey)
			if fp != "" {
				if _, exists := tombstones[fp]; !exists {
					tombstones[fp] = &Tombstone{DNSKey: ta.DNSKey, FirstSeen: ta.FirstSeen}
				}
			}
		}
	}

	// Enforce tombstone precedence over any kskCurrent entry. This
	// covers the first-run fallback branch, which seeds kskCurrent
	// from cfg.RootKeys as Valid before the merge-loop tombstone
	// check can run — a revoked key lingering in config would
	// otherwise be republished as active trust material. Skip
	// StateRevoked/StateRemoved entries: they *are* the revocation
	// markers we just migrated into tombstones, and dropping them
	// here before a durable tombstones write would lose the
	// revocation if the write fails.
	for tag, ta := range kskCurrent {
		if ta.State == StateRevoked || ta.State == StateRemoved {
			continue
		}
		if _, tombstoned := tombstones[dnskeyMaterialFP(ta.DNSKey)]; tombstoned {
			zlog.Warn("Seeded trust anchor is tombstoned — dropping", "keytag", tag)
			delete(kskCurrent, tag)
		}
	}

	// Merge admin-configured root keys into state. Keys placed in
	// cfg.RootKeys are trust anchors of record — they must not be
	// silently dropped just because the state file was written before
	// the operator added them. Use configuredRootKeys (the immutable
	// startup snapshot) rather than r.rootKeys: r.rootKeys is
	// rewritten every refresh and could still carry a key that was
	// deleted from state during this run, which would resurrect it
	// on the next tick.
	for _, rr := range r.configuredRootKeys {
		dnskey, ok := rr.(*dns.DNSKEY)
		if !ok || dnskey.Flags&DNSKEYFlagKSK == 0 {
			continue
		}
		tag := dnskey.KeyTag()
		if _, exists := kskCurrent[tag]; exists {
			continue
		}
		// Tombstone check by key material. RFC 5011 §2.1 requires
		// revocation to be "immediate and permanent" — a stale admin
		// config must not resurrect a revoked key, and the check is
		// by cryptographic identity, not key tag.
		if _, tombstoned := tombstones[dnskeyMaterialFP(dnskey)]; tombstoned {
			zlog.Info("Skipping admin-configured trust anchor — tombstoned", "keytag", tag)
			continue
		}
		if dnskey.Flags&DNSKEYFlagRevoke != 0 {
			// Admin explicitly pre-seeded a revoked key. Record the
			// tombstone and do not insert into active anchors.
			tombstones[dnskeyMaterialFP(dnskey)] = &Tombstone{DNSKey: dnskey, FirstSeen: time.Now()}
			zlog.Info("Admin-configured trust anchor carries REVOKE bit — recorded as tombstone", "keytag", tag)
			continue
		}
		zlog.Info("Adding admin-configured trust anchor to state", "keytag", tag)
		kskCurrent[tag] = &TrustAnchor{
			DNSKey:    dnskey,
			State:     StateValid,
			FirstSeen: time.Now(),
		}
	}

	// Build a candidate trust set from kskCurrent. Per RFC 5011
	// §4.2, Missing keys remain valid trust anchors until remove
	// hold-down expires.
	candidate := []dns.RR{}
	for _, ta := range kskCurrent {
		if ta.State == StateValid || ta.State == StateMissing {
			candidate = append(candidate, ta.DNSKey)
		}
	}

	for _, k := range candidate {
		validTag := k.(*dns.DNSKEY).KeyTag()
		ok := false
		for _, kv := range r.configuredRootKeys {
			currTag := kv.(*dns.DNSKEY).KeyTag()
			if currTag == validTag {
				ok = true
			}
		}
		if !ok {
			zlog.Warn("Please update missing rootkeys in config", "keytag", validTag)
		}
	}

	// Publish the tombstone-filtered candidate now, but only when
	// the prior trust set was valid (initial config seed or a
	// successful previous run). This guarantees that tombstoned or
	// removed keys exit r.rootKeys *before* the external DNSKEY
	// fetch can return early — otherwise NewResolver's cfg.RootKeys
	// copy would keep a revoked-but-still-configured key trusted
	// until the next successful refresh. When priorTrustValid is
	// false the resolver is already in the persistence-failed
	// fail-closed mode, and we leave r.rootKeys empty until a write
	// actually succeeds at the end of this run.
	if priorTrustValid {
		r.Lock()
		r.rootKeys = candidate
		r.Unlock()
	}

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeDNSKEY)
	req.SetEdns0(util.DefaultMsgSize, true)
	// CD=true on AutoTA's own DNSKEY query: we validate the response
	// explicitly against `candidate` below, so the recursive
	// resolver's validator must not gate on r.rootKeys (which may
	// be empty after a previous persistence failure or before the
	// first successful refresh has published).
	req.CheckingDisabled = true

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.netTimeout))
	defer cancel()

	resp, err := r.Resolve(ctx, req, r.rootServers, true, 5, 0, false, nil, true)
	if err != nil {
		zlog.Error("Refresh trust anchors failed", "error", err.Error())
		return
	}

	ok, revocationOnly, err := verifyFetchedKeys(candidate, resp.Answer)
	if !ok {
		zlog.Error("Refresh trust anchors failed", "error", err.Error())
		return
	}
	if revocationOnly {
		zlog.Warn("Fetched root DNSKEY RRset authenticated only by revoked-key self-signature — restricting to revocation processing")
	}

	kskFetched := make(TrustAnchors)

	for _, rr := range resp.Answer {
		if dnskey, ok := rr.(*dns.DNSKEY); ok {
			if dnskey.Flags&DNSKEYFlagKSK != 0 {
				keyTag := dnskey.KeyTag()
				ta := &TrustAnchor{
					DNSKey: dnskey,
					State:  StateStart,
				}

				kskFetched[keyTag] = ta
			}
		}
	}

	for tag, ta := range kskFetched {
		// Tombstoned by material? RFC 5011 §2.1 says revocation is
		// permanent — ignore this fetched key regardless of tag.
		if _, tombstoned := tombstones[dnskeyMaterialFP(ta.DNSKey)]; tombstoned {
			continue
		}

		existing := kskCurrent[tag]
		// Already tracked with matching material — nothing to do.
		if existing != nil &&
			existing.DNSKey.Algorithm == ta.DNSKey.Algorithm &&
			existing.DNSKey.Protocol == ta.DNSKey.Protocol &&
			existing.DNSKey.PublicKey == ta.DNSKey.PublicKey &&
			existing.DNSKey.Flags == ta.DNSKey.Flags {
			continue
		}

		if ta.DNSKey.Flags&DNSKEYFlagRevoke != 0 {
			oldTag := tag - DNSKEYFlagRevoke
			oldTA := kskCurrent[oldTag]
			// RFC 5011 §4 state table: both Valid + RevBit and
			// Missing + RevBit transition to revoked. Since Missing
			// anchors still sit in r.rootKeys until the remove
			// hold-down expires, we have to honour revocation for
			// them too; otherwise a missing-then-revoked key would
			// remain trusted for up to 90 days.
			if oldTA != nil && (oldTA.State == StateValid || oldTA.State == StateMissing) {
				// RFC 5011 §2.1: revocation is valid only if the
				// revoked key itself signed the DNSKEY RRset that
				// contains it, AND the revoked key is actually
				// the trust anchor (key-material match, not just
				// a colliding tag).
				if !sameKeyExceptRevoke(oldTA.DNSKey, ta.DNSKey) {
					zlog.Warn("Trust anchor REVOKE bit matches tag but not key material — ignoring revocation", "keytag", tag)
					continue
				}
				if !revocationIsSelfSigned(resp.Answer, ta.DNSKey) {
					zlog.Warn("Trust anchor REVOKE bit present but no valid self-signed RRSIG — ignoring revocation", "keytag", tag)
					continue
				}
				zlog.Warn("Trust anchor revoked!", "keytag", tag)
				tombstones[dnskeyMaterialFP(ta.DNSKey)] = &Tombstone{DNSKey: ta.DNSKey, FirstSeen: time.Now()}
				newRevocation = true
				// Keep the entry in kskCurrent as StateRevoked
				// instead of deleting. This dual-writes the
				// revocation: if the tombstones file write fails,
				// the main state file still records StateRevoked,
				// which the legacy-migration loop at the top of
				// AutoTA will retry on the next run. finalRootKeys
				// only admits StateValid|StateMissing, so a Revoked
				// entry still stays out of r.rootKeys. The redundant
				// marker is removed after a successful tombstones
				// write (see the post-write cleanup below).
				oldTA.State = StateRevoked
				oldTA.FirstSeen = time.Now()
			}
			continue
		}

		// New-key processing. Unsafe under revocation-only
		// authentication — RFC 5011 §2.1 restricts revoked-key
		// signatures to validating the revocation itself, not
		// seeding new trust anchors.
		if revocationOnly {
			continue
		}

		// Tag collision with an unrelated active anchor is
		// vanishingly rare but would silently overwrite real trust
		// material. Log and skip rather than corrupt state.
		if existing != nil {
			zlog.Warn("Fetched KSK tag collides with different active key — ignoring new key", "keytag", tag)
			continue
		}

		// found new ksk
		zlog.Warn("New trust anchor found! Pending for hold-down", "keytag", tag, "hold-down", "30d")
		ta.State = StateAddPend
		ta.FirstSeen = time.Now()
		kskCurrent[tag] = ta
	}

	// The KeyRem / KeyPres / add-hold-down transitions below infer
	// "key is no longer in the zone" or "key is still in the zone"
	// from the fetched RRset. That inference is only sound when the
	// RRset was fully authenticated by a non-revoked trust anchor —
	// revocation-only auth (RFC 5011 §2.1) cannot speak to absent
	// keys or to adjacent state changes.
	if !revocationOnly {
		for tag, ta := range kskCurrent {
			if kskFetched[tag] == nil {
				// RFC 5011 §4 state table: the KeyRem event's effect
				// depends on the prior state.
				switch ta.State {
				case StateAddPend, StateStart:
					// Add hold-down aborts: the candidate key never
					// completed its 30d waiting period, and a validated
					// RRset now omits it. Delete without tombstoning —
					// if the root republishes the key later, a fresh
					// AddPend cycle is the correct response.
					zlog.Warn("Trust anchor pending but absent from fetched RRset — aborting add hold-down", "keytag", tag)
					delete(kskCurrent, tag)
					continue
				case StateValid:
					// Previously-valid key disappeared. Enter Missing;
					// per §4.2 the key remains a valid trust anchor
					// until the remove hold-down expires.
					zlog.Warn("Trust anchor missing! Please check it manually", "keytag", tag, "hold-down", "90d")
					ta.State = StateMissing
					ta.FirstSeen = time.Now()
				}

				// Missing keys age out after the hold-down. RFC 5011
				// §2.4.2 describes remove-hold-down as a bookkeeping
				// parameter — the deletion isn't a security boundary,
				// so we don't tombstone. RFC 5011 §2.1 reserves
				// "immediate and permanent" semantics for RevBit
				// revocations; an admin-configured key that simply
				// disappeared from the root may legitimately be
				// reintroduced and should be allowed back through
				// AddPend if the root republishes it.
				if ta.State == StateMissing && time.Since(ta.FirstSeen) > 2160*time.Hour { // hold-down 90 days
					zlog.Warn("Trust anchor deleted after hold-down", "keytag", tag)
					delete(kskCurrent, tag)
				}
				continue
			}

			if ta.State == StateAddPend && time.Since(ta.FirstSeen) > 720*time.Hour { // hold-down 30days
				// now valid
				zlog.Warn("Trust anchor now valid!", "keytag", tag)
				ta.State = StateValid
			}

			if ta.State == StateMissing {
				// RFC 5011 §4 state table: a Missing key re-appearing in
				// a validated DNSKEY RRset (KeyPres event) transitions
				// straight back to Valid. It was already a trust anchor
				// — the absence was transient, and forcing another
				// AddPend hold-down would strip trust for 30 days even
				// though nothing about the key's authority changed.
				zlog.Info("Missing trust anchor reappeared — restored to Valid", "keytag", tag)
				ta.State = StateValid
			}
		}
	}

	// Persist tombstones first. On success we can drop transitional
	// StateRevoked markers from main state (they were only there to
	// survive a tombstone-write failure). On failure we still write
	// state so the StateRevoked markers persist — the legacy
	// migration loop at the top of AutoTA re-tries the tombstone
	// move next run, and the post-success r.rootKeys publish below
	// excludes Revoked from the live trust set, so the key stays
	// fail-closed across retries.
	tombErr := writeTombstones(tombstonePath, tombstones)
	if tombErr != nil {
		zlog.Error("Refresh trust anchor tombstones failed — revocation kept in state as StateRevoked for next-run retry", "error", tombErr.Error())
	} else {
		// Tombstones are durable; drop the in-state markers for
		// both this run's newly-revoked keys and any legacy
		// Revoked/Removed entries migrated above.
		for tag, ta := range kskCurrent {
			if ta.State == StateRevoked || ta.State == StateRemoved {
				delete(kskCurrent, tag)
			}
		}
	}
	stateErr := writeToTAFile(filename, kskCurrent)
	if stateErr != nil {
		zlog.Error("Refresh trust anchors state write failed", "error", stateErr.Error())
	}

	// Publication policy: r.rootKeys is the live trust set that
	// query validation paths consult. We refresh it only after a
	// successful state mutation has been durably recorded — either
	// tombstones or the main state file must reflect this run's
	// outcome before we let it influence validation. The fail-
	// closed clear is gated on newRevocation: only a brand-new
	// revocation that exists *only* in memory creates a real
	// "trusting more than disk knows" exposure. An unrelated
	// refresh on a read-only/full directory would otherwise turn
	// working trust anchors into total SERVFAIL just because the
	// tombstones/state write failed for an orthogonal reason.
	if tombErr != nil && stateErr != nil && newRevocation {
		zlog.Error("Refresh trust anchors: both tombstones and state writes failed during a new revocation — clearing in-memory trust set to fail closed")
		r.Lock()
		r.rootKeys = nil
		r.Unlock()
		return
	}
	if tombErr != nil && stateErr != nil {
		zlog.Error("Refresh trust anchors: both tombstones and state writes failed (no new revocation this run) — keeping current trust set")
		return
	}

	finalRootKeys := []dns.RR{}
	for _, ta := range kskCurrent {
		if ta.State == StateValid || ta.State == StateMissing {
			finalRootKeys = append(finalRootKeys, ta.DNSKey)
		}
	}
	r.Lock()
	r.rootKeys = finalRootKeys
	r.Unlock()

	for tag, ta := range kskCurrent {
		zlog.Info("Trust anchor status", "keytag", tag, "state", ta.State.String(), "firstseen", ta.FirstSeen.UTC().Format(time.UnixDate))
	}
	for fp, tb := range tombstones {
		zlog.Info("Trust anchor tombstone", "keytag", tb.DNSKey.KeyTag(), "fp", fp, "firstseen", tb.FirstSeen.UTC().Format(time.UnixDate))
	}

	zlog.Info("Trust anchors refreshed", "path", filename, "nextrefresh", time.Now().Add(12*time.Hour).UTC().Format(time.UnixDate))
}

// sameKeyExceptRevoke reports whether revokedKey is the same DNSKEY
// as currentKey with only the REVOKE bit toggled. Key tags are 16-bit
// checksums and can collide, so identifying a revocation by tag alone
// would let an unrelated self-signed key authenticate as a revocation
// of the real trust anchor. Comparing the actual key material
// (algorithm, protocol, public key, and flags modulo REVOKE) closes
// that gap.
func sameKeyExceptRevoke(currentKey, revokedKey *dns.DNSKEY) bool {
	if currentKey == nil || revokedKey == nil {
		return false
	}
	if currentKey.Algorithm != revokedKey.Algorithm {
		return false
	}
	if currentKey.Protocol != revokedKey.Protocol {
		return false
	}
	if currentKey.PublicKey != revokedKey.PublicKey {
		return false
	}
	if currentKey.Flags != revokedKey.Flags^DNSKEYFlagRevoke {
		return false
	}
	return true
}

// revocationIsSelfSigned reports whether revokedKey (a DNSKEY carrying
// the REVOKE bit) has a valid RRSIG over the DNSKEY RRset it was
// fetched in, produced by revokedKey itself. Per RFC 5011 §2.1 this
// self-signature is a precondition for accepting a revocation.
func revocationIsSelfSigned(rrs []dns.RR, revokedKey *dns.DNSKEY) bool {
	dnskeys := extractRRSet(rrs, "", dns.TypeDNSKEY)
	if len(dnskeys) == 0 {
		return false
	}
	rrsigs := extractRRSet(rrs, "", dns.TypeRRSIG)
	revokedTag := revokedKey.KeyTag()
	for _, rr := range rrsigs {
		rrsig := rr.(*dns.RRSIG)
		if rrsig.KeyTag != revokedTag {
			continue
		}
		if rrsig.TypeCovered != dns.TypeDNSKEY {
			continue
		}
		if rrsig.SignerName != revokedKey.Header().Name {
			continue
		}
		if err := rrsig.Verify(revokedKey, dnskeys); err != nil {
			continue
		}
		if !rrsig.ValidityPeriod(time.Time{}) {
			continue
		}
		return true
	}
	return false
}

// verifyFetchedKeys authenticates a freshly fetched root DNSKEY RRset
// against the currently trusted KSKs per RFC 5011 §2.2: the RRset is
// accepted if *at least one* RRSIG from a currently-valid trust anchor
// verifies it. RRSIGs from unknown keys (e.g. a newly published KSK
// that hasn't cleared hold-down yet) are ignored rather than treated
// as failure — this is required for KSK rollovers where the zone is
// co-signed by the old and new KSK.
//
// Revoked keys are a narrow exception. Per RFC 5011 §2.1 a revoked
// key may be used "to validate the RRSIG it signed over the DNSKEY
// RRSet specifically for the purpose of validating the revocation".
// The returned revocationOnly flag indicates that no non-revoked
// currently-trusted anchor signed the RRset: only revocation
// processing is safe against that response, and the caller must not
// drive any other state transition (AddPend seeding, Missing
// marking, etc.) from it.
func verifyFetchedKeys(rootKeys []dns.RR, rrs []dns.RR) (ok bool, revocationOnly bool, err error) {
	fetchedkeys := extractRRSet(rrs, "", dns.TypeDNSKEY)
	if len(fetchedkeys) == 0 {
		return false, false, errNoDNSKEY
	}

	currentKeys := make(map[uint16]*dns.DNSKEY)
	for _, r := range rootKeys {
		dnskey := r.(*dns.DNSKEY)
		if dnskey.Flags&DNSKEYFlagKSK != 0 {
			currentKeys[dnskey.KeyTag()] = dnskey
		}
	}

	if len(currentKeys) == 0 {
		return false, false, errMissingKSK
	}

	// Revoked DNSKEYs whose *key material* matches a current trust
	// anchor (with only the REVOKE bit toggled). Their RRSIGs are
	// allowed to authenticate the RRset as the RFC 5011 §2.1
	// "validate the revocation" carve-out. A tag-only match would
	// be unsafe: key tags are 16-bit checksums and an attacker
	// could craft an unrelated self-signed revoked key that
	// collides on tag.
	revokedBootstrap := make(map[uint16]*dns.DNSKEY)
	for _, r := range fetchedkeys {
		dnskey := r.(*dns.DNSKEY)
		if dnskey.Flags&DNSKEYFlagRevoke == 0 {
			continue
		}
		candidate := currentKeys[dnskey.KeyTag()-DNSKEYFlagRevoke]
		if sameKeyExceptRevoke(candidate, dnskey) {
			revokedBootstrap[dnskey.KeyTag()] = dnskey
		}
	}

	rrsigs := extractRRSet(rrs, "", dns.TypeRRSIG)
	if len(rrsigs) == 0 {
		return false, false, errNoSignatures
	}

	var lastErr error = errMissingDNSKEY

	// Pass 1: non-revoked current trust anchors. A success here is
	// full authentication — the caller may process any state
	// transition against this RRset.
	for _, rr := range rrsigs {
		rrsig := rr.(*dns.RRSIG)
		k, known := currentKeys[rrsig.KeyTag]
		if !known {
			continue
		}
		if verifyOneRRSIG(rrsig, k, fetchedkeys, &lastErr) {
			return true, false, nil
		}
	}

	// Pass 2: revoked-bootstrap. A success here authenticates only
	// the revocation itself; the caller must restrict processing to
	// the revocation path (RFC 5011 §2.1).
	for _, rr := range rrsigs {
		rrsig := rr.(*dns.RRSIG)
		k, known := revokedBootstrap[rrsig.KeyTag]
		if !known {
			continue
		}
		if verifyOneRRSIG(rrsig, k, fetchedkeys, &lastErr) {
			return true, true, nil
		}
	}

	return false, false, lastErr
}

// verifyOneRRSIG runs the per-signature checks for verifyFetchedKeys.
// Returns true if the signature authenticates fetchedkeys under k;
// otherwise updates *lastErr with the most informative failure.
func verifyOneRRSIG(rrsig *dns.RRSIG, k *dns.DNSKEY, fetchedkeys []dns.RR, lastErr *error) bool {
	if rrsig.SignerName != k.Header().Name {
		*lastErr = errMissingSigned
		return false
	}
	rest := extractRRSet(fetchedkeys, rrsig.Header().Name, rrsig.TypeCovered)
	if len(rest) == 0 {
		*lastErr = errMissingSigned
		return false
	}
	if err := rrsig.Verify(k, rest); err != nil {
		*lastErr = err
		return false
	}
	if !rrsig.ValidityPeriod(time.Time{}) {
		*lastErr = errInvalidSignaturePeriod
		return false
	}
	return true
}

func readFromTAFile(filename string) (TrustAnchors, error) {
	f, err := os.Open(filename) //nolint:gosec // G304 - filename from config, admin controlled
	if err != nil {
		return nil, err
	}

	dec := gob.NewDecoder(f)
	kskCurrent := make(TrustAnchors)

	err = dec.Decode(&kskCurrent)
	if err != nil {
		return nil, err
	}

	_ = f.Close()

	return kskCurrent, nil
}

func writeToTAFile(filename string, kskCurrent TrustAnchors) error {
	return atomicGobWrite(filename, &kskCurrent)
}

func readTombstones(filename string) (Tombstones, error) {
	f, err := os.Open(filename) //nolint:gosec // G304 - filename from config, admin controlled
	if err != nil {
		if os.IsNotExist(err) {
			return make(Tombstones), nil
		}
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	t := make(Tombstones)
	if err := gob.NewDecoder(f).Decode(&t); err != nil {
		// Wrap so AutoTA can distinguish "I read bytes that don't
		// parse" (real corruption — fail closed) from "I couldn't
		// open the file at all" (transient, e.g. Windows sharing
		// violation during a concurrent rename).
		return nil, fmt.Errorf("%w: %v", errCorruptTombstones, err)
	}
	return t, nil
}

func writeTombstones(filename string, t Tombstones) error {
	return atomicGobWrite(filename, &t)
}

// atomicGobWrite encodes v with gob to filename via a temp-file +
// fsync + rename + dirsync sequence. A crash or power loss before
// rename leaves the original file intact; after rename + parent
// fsync the new directory entry is durable. Callers that need
// strict write ordering across multiple files can rely on the
// post-return state to be the full previous content, never a
// half-written intermediate. The temp file name is randomized so
// concurrent writers (e.g. parallel test goroutines sharing a
// directory) can safely race — each owns its own tmp inode until
// rename.
//
// The parent-directory fsync matters for ordering: tombstones are
// written before the main state file, and the caller drops in-state
// revocation markers only after this returns success. Without the
// directory sync, a crash could leave the file contents on disk but
// lose the directory entry update, so a remount could see the old
// state file with no tombstone — exactly the "lost revocation"
// failure mode dual-writes are meant to prevent.
func atomicGobWrite(filename string, v interface{}) error {
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, filepath.Base(filename)+".tmp.*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if err := gob.NewEncoder(f).Encode(v); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filename); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// Best-effort durability for the rename's directory-entry
	// update. On POSIX this is an fsync of the parent directory;
	// on Windows it's a no-op (the OS doesn't expose directory
	// fsync, NTFS journals metadata).
	return syncDir(dir)
}
