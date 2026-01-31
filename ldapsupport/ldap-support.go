package ldapsupport

import "github.com/go-ldap/ldap/v3"

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
