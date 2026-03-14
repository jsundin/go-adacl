package ldapsupport

import (
	"slices"

	"github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

const (
	LDAP_PAGING_SIZE = 1000
)

const (
	SDFLAGS_OWNER_SECURITY_INFORMATION = 0x01
	SDFLAGS_GROUP_SECURITY_INFORMATION = 0x02
	SDFLAGS_DACL_SECURITY_INFORMATION  = 0x04
	SDFLAGS_SACL_SECURITY_INFORMATION  = 0x08
)

func ChildDN(parent *ldap.DN, rdns []*ldap.RelativeDN) *ldap.DN {
	// Copy RDNs to avoid mutating the original DN
	newRDNs := make([]*ldap.RelativeDN, 0, len(parent.RDNs)+1)
	newRDNs = append(newRDNs, rdns...)
	newRDNs = append(newRDNs, parent.RDNs...)

	return &ldap.DN{RDNs: newRDNs}
}

func MustParseDN(dnStr string) *ldap.DN {
	dn, err := ldap.ParseDN(dnStr)
	if err != nil {
		panic(err)
	}
	return dn
}

func UnmarshalGuid(b []byte) (uuid.UUID, error) {
	w := make([]byte, len(b))
	copy(w, b)
	part1 := w[0:4]
	part2 := w[4:6]
	part3 := w[6:8]
	slices.Reverse(part1)
	slices.Reverse(part2)
	slices.Reverse(part3)

	return uuid.FromBytes(w)
}
