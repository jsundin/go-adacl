package filters

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/jsundin/go-adacl/collector"
	"github.com/jsundin/go-adacl/ldapsupport"
)

type dnMatcher struct {
	dns []*ldap.DN
}

func NewDnMatcher(dns []*ldap.DN) dnMatcher {
	return dnMatcher{
		dns: dns,
	}
}

func NewDnMatcherStrings(dns []string) dnMatcher {
	resolved := []*ldap.DN{}
	for _, dn := range dns {
		resolved = append(resolved, ldapsupport.MustParseDN(dn))
	}
	return NewDnMatcher(resolved)
}

func NewRelativeDnMatcher(baseDN string, rdns []string) dnMatcher {
	dn := ldapsupport.MustParseDN(baseDN)
	dns := []*ldap.DN{}
	for _, rdn := range rdns {
		dns = append(dns, ldapsupport.ChildDN(dn, ldapsupport.MustParseDN(rdn).RDNs))
	}
	return NewDnMatcher(dns)
}

func (m dnMatcher) matches(dn string, ace *collector.AceEntry) bool {
	parsedDN := ldapsupport.MustParseDN(dn)
	for _, dnToMatch := range m.dns {
		if dnToMatch.EqualFold(parsedDN) || dnToMatch.AncestorOfFold(parsedDN) {
			return true
		}
	}
	return false
}
