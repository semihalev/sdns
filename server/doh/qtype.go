package doh

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var qtype = map[string]uint16{
	"A":          dns.TypeA,
	"AAAA":       dns.TypeAAAA,
	"AFSDB":      dns.TypeAFSDB,
	"AMTRELAY":   dns.TypeAMTRELAY,
	"ANY":        dns.TypeANY,
	"APL":        dns.TypeAPL,
	"ATMA":       dns.TypeATMA,
	"AVC":        dns.TypeAVC,
	"AXFR":       dns.TypeAXFR,
	"CAA":        dns.TypeCAA,
	"CDNSKEY":    dns.TypeCDNSKEY,
	"CDS":        dns.TypeCDS,
	"CERT":       dns.TypeCERT,
	"CNAME":      dns.TypeCNAME,
	"CSYNC":      dns.TypeCSYNC,
	"DHCID":      dns.TypeDHCID,
	"DLV":        dns.TypeDLV,
	"DNAME":      dns.TypeDNAME,
	"DNSKEY":     dns.TypeDNSKEY,
	"DS":         dns.TypeDS,
	"EID":        dns.TypeEID,
	"EUI48":      dns.TypeEUI48,
	"EUI64":      dns.TypeEUI64,
	"GID":        dns.TypeGID,
	"GPOS":       dns.TypeGPOS,
	"HINFO":      dns.TypeHINFO,
	"HIP":        dns.TypeHIP,
	"HTTPS":      dns.TypeHTTPS,
	"IPSECKEY":   dns.TypeIPSECKEY,
	"ISDN":       dns.TypeISDN,
	"IXFR":       dns.TypeIXFR,
	"KEY":        dns.TypeKEY,
	"KX":         dns.TypeKX,
	"L32":        dns.TypeL32,
	"L64":        dns.TypeL64,
	"LOC":        dns.TypeLOC,
	"LP":         dns.TypeLP,
	"MAILA":      dns.TypeMAILA,
	"MAILB":      dns.TypeMAILB,
	"MB":         dns.TypeMB,
	"MD":         dns.TypeMD,
	"MF":         dns.TypeMF,
	"MG":         dns.TypeMG,
	"MINFO":      dns.TypeMINFO,
	"MR":         dns.TypeMR,
	"MX":         dns.TypeMX,
	"NAPTR":      dns.TypeNAPTR,
	"NID":        dns.TypeNID,
	"NIMLOC":     dns.TypeNIMLOC,
	"NINFO":      dns.TypeNINFO,
	"NS":         dns.TypeNS,
	"NSAP-PTR":   dns.TypeNSAPPTR,
	"NSEC":       dns.TypeNSEC,
	"NSEC3":      dns.TypeNSEC3,
	"NSEC3PARAM": dns.TypeNSEC3PARAM,
	"NULL":       dns.TypeNULL,
	"NXT":        dns.TypeNXT,
	"None":       dns.TypeNone,
	"OPENPGPKEY": dns.TypeOPENPGPKEY,
	"OPT":        dns.TypeOPT,
	"PTR":        dns.TypePTR,
	"PX":         dns.TypePX,
	"RKEY":       dns.TypeRKEY,
	"RP":         dns.TypeRP,
	"RRSIG":      dns.TypeRRSIG,
	"RT":         dns.TypeRT,
	"Reserved":   dns.TypeReserved,
	"SIG":        dns.TypeSIG,
	"SMIMEA":     dns.TypeSMIMEA,
	"SOA":        dns.TypeSOA,
	"SPF":        dns.TypeSPF,
	"SRV":        dns.TypeSRV,
	"SSHFP":      dns.TypeSSHFP,
	"SVCB":       dns.TypeSVCB,
	"TA":         dns.TypeTA,
	"TALINK":     dns.TypeTALINK,
	"TKEY":       dns.TypeTKEY,
	"TLSA":       dns.TypeTLSA,
	"TSIG":       dns.TypeTSIG,
	"TXT":        dns.TypeTXT,
	"UID":        dns.TypeUID,
	"UINFO":      dns.TypeUINFO,
	"UNSPEC":     dns.TypeUNSPEC,
	"URI":        dns.TypeURI,
	"X25":        dns.TypeX25,
	"ZONEMD":     dns.TypeZONEMD,
}

// ParseQTYPE function.
func ParseQTYPE(s string) uint16 {
	if s == "" {
		return dns.TypeA
	}

	if v, err := strconv.ParseUint(s, 10, 16); err == nil {
		return uint16(v)
	}

	if v, ok := qtype[strings.ToUpper(s)]; ok {
		return v
	}

	return dns.TypeNone
}
