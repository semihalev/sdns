package resolver

import (
	"context"
	"encoding/gob"
	"os"
	"path/filepath"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/dnsutil"
)

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
	stateFile = "trust-anchor.db"
)

type TrustAnchor struct {
	DNSKey      *dns.DNSKEY
	State       State
	FirstSeen   time.Time
	NextRefresh time.Time
}

type TrustAnchors map[uint16]*TrustAnchor

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

	kskCurrent, err := readFromTAFile(filename)
	if err != nil {
		log.Warn("No trust anchor state file found or the state corrupted! New one will be generate.", "path", filename)

		kskCurrent = make(TrustAnchors)

		for _, rr := range r.rootkeys {
			if dnskey, ok := rr.(*dns.DNSKEY); ok {
				if dnskey.Flags&DNSKEYFlagKSK != 0 {
					keyTag := dnskey.KeyTag()
					ta := &TrustAnchor{
						DNSKey:      dnskey,
						State:       StateValid,
						FirstSeen:   time.Now(),
						NextRefresh: time.Now().Add(12 * time.Hour),
					}

					if dnskey.Flags&DNSKEYFlagRevoke != 0 {
						ta.State = StateRevoked
					}

					kskCurrent[keyTag] = ta
				}
			}
		}
	}

	rootkeys := []dns.RR{}
	for _, ta := range kskCurrent {
		if ta.State == StateValid {
			rootkeys = append(rootkeys, ta.DNSKey)
		}
	}

	//TODO: check datarace
	r.rootkeys = rootkeys

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeDNSKEY)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(r.netTimeout))
	defer cancel()

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 5, 0, false, nil, true)
	if err != nil {
		log.Error("Refresh trust anchors failed", "error", err.Error())
		return
	}

	if ok, err := verifyFetchedKeys(r.rootkeys, resp.Answer); !ok {
		log.Error("Refresh trust anchors failed", "error", err.Error())
		return
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
		if kskCurrent[tag] == nil {
			if ta.DNSKey.Flags&DNSKEYFlagRevoke != 0 {
				oldTag := tag - DNSKEYFlagRevoke
				if kskCurrent[oldTag] != nil && kskCurrent[oldTag].State == StateValid {
					//revoked ksk
					log.Crit("Trust anchor revoked!", "keytag", tag)
					ta.State = StateRevoked
					ta.FirstSeen = time.Now()
					kskCurrent[tag] = ta

					// delete old stand-by ksk
					delete(kskCurrent, oldTag)
				}
				continue
			}

			//found new ksk
			log.Crit("New trust anchor found! Pending for hold-down", "keytag", tag, "hold-down", "30d")
			kskCurrent[tag] = ta
			ta.State = StateAddPend
			ta.FirstSeen = time.Now()
		}
	}

	for tag, ta := range kskCurrent {
		if kskFetched[tag] == nil {
			if ta.State == StateRevoked {
				log.Crit("Trust anchor removed! Pending for hold-down", "keytag", tag, "hold-down", "90d")
				ta.State = StateRemoved
				ta.FirstSeen = time.Now()
				//ta removed, no refresh anymore
			} else if ta.State != StateRemoved && ta.State != StateMissing {
				log.Crit("Trust anchor missing! Please check it manually", "keytag", tag, "hold-down", "90d")
				ta.State = StateMissing
				ta.FirstSeen = time.Now()
			}

			if (ta.State == StateRemoved || ta.State == StateMissing) && time.Since(ta.FirstSeen) > 2160*time.Hour { //hold-down 90 days
				// we can delete this safely now
				log.Crit("Trust anchor deleted!", "keytag", tag)
				delete(kskCurrent, tag)
			}
			continue
		}

		if ta.State == StateAddPend && time.Since(ta.FirstSeen) > 720*time.Hour { //hold-down 30days
			// now valid
			log.Crit("Trust anchor now valid!", "keytag", tag)
			ta.State = StateValid
		}

		ta.NextRefresh = time.Now().Add(12 * time.Hour)
	}

	err = writeToTAFile(filename, kskCurrent)
	if err != nil {
		log.Error("Refresh trust anchors failed", "error", err.Error())
		return
	}

	for tag, ta := range kskCurrent {
		log.Info("Trust anchor status", "keytag", tag, "state", ta.State.String(), "firstseen", ta.FirstSeen.UTC().Format(time.UnixDate))
	}

	log.Info("Trust anchors refreshed successfuly", "path", filename)
}

func verifyFetchedKeys(rootkeys []dns.RR, rrs []dns.RR) (ok bool, err error) {
	fetchedkeys := extractRRSet(rrs, "", dns.TypeDNSKEY)
	if len(fetchedkeys) == 0 {
		return false, errNoDNSKEY
	}

	currentKeys := make(map[uint16]*dns.DNSKEY)
	for _, r := range rootkeys {
		dnskey := r.(*dns.DNSKEY)
		if dnskey.Flags&DNSKEYFlagKSK != 0 {
			currentKeys[dnskey.KeyTag()] = dnskey
		}
	}

	if len(currentKeys) == 0 {
		return false, errMissingKSK
	}

	revokedKeys := make(map[uint16]*dns.DNSKEY)
	for _, r := range fetchedkeys {
		dnskey := r.(*dns.DNSKEY)
		if dnskey.Flags&DNSKEYFlagRevoke != 0 {
			revokedKeys[dnskey.KeyTag()] = dnskey
		}
	}

	rrsigs := extractRRSet(rrs, "", dns.TypeRRSIG)
	for i, rr := range rrsigs {
		rrsig := rr.(*dns.RRSIG)
		if revokedKeys[rrsig.KeyTag] != nil {
			rrsigs = append(rrsigs[:i], rrsigs[i+1:]...)
		}
	}

	if len(rrsigs) == 0 {
		return false, errNoSignatures
	}

	for _, rr := range rrsigs {
		rrsig := rr.(*dns.RRSIG)

		for _, k := range currentKeys {
			if rrsig.SignerName != k.Header().Name {
				return false, errMissingSigned
			}
		}

		rest := extractRRSet(fetchedkeys, rrsig.Header().Name, rrsig.TypeCovered)
		if len(rest) == 0 {
			return false, errMissingSigned
		}

		k, ok := currentKeys[rrsig.KeyTag]
		if !ok {
			return false, errMissingDNSKEY
		}

		err := rrsig.Verify(k, rest)
		if err != nil {
			return false, err
		}

		if !rrsig.ValidityPeriod(time.Time{}) {
			return false, errInvalidSignaturePeriod
		}
	}

	return true, nil
}

func readFromTAFile(filename string) (TrustAnchors, error) {
	f, err := os.Open(filename)
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
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	enc := gob.NewEncoder(f)
	err = enc.Encode(&kskCurrent)
	if err != nil {
		return err
	}

	return f.Close()
}
