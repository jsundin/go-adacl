package collector

import (
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
)

type SidResolverContext struct {
	visitedDNs []string
	sids       []string
}

func newSidResolverContext() *SidResolverContext {
	return &SidResolverContext{
		sids: []string{
			"S-1-1-0",  // Everyone
			"S-1-5-11", // Authenticated Users
		},
	}
}

func (cr *Collector) GetAllSidsForPrincipal(name string, src *SidResolverContext) []string {
	if src == nil {
		src = newSidResolverContext()
	}

	for _, p := range cr.PrincipalsByDN {
		if strings.EqualFold(p.Name, name) {
			cr.GetAllSidsForDN(p.DN, src)
		}
	}

	return src.sids
}

func (cr *Collector) GetAllSidsForSid(sid string, src *SidResolverContext) []string {
	if src == nil {
		src = newSidResolverContext()
	}
	for _, p := range cr.PrincipalsByDN {
		if strings.EqualFold(p.Sid, sid) {
			cr.GetAllSidsForDN(p.DN, src)
		}
	}
	return src.sids
}

func (cr *Collector) GetAllSidsForDN(dn string, src *SidResolverContext) []string {
	if src == nil {
		src = newSidResolverContext()
	}

	if slices.Contains(src.visitedDNs, dn) {
		return src.sids
	}
	src.visitedDNs = append(src.visitedDNs, dn)

	p, found := cr.PrincipalsByDN[dn]
	if !found {
		return src.sids
	}

	logrus.Debugf("adding sid '%s' (%s)", p.Sid, p.DN)
	src.sids = append(src.sids, p.Sid)

	p.PrimaryGroupRid.IfPresent(func(rid string) {
		parts := strings.Split(p.Sid, "-")
		primaryGroupSid := strings.Join(append(parts[0:len(parts)-1], rid), "-")
		cr.GetAllSidsForSid(primaryGroupSid, src)
	})

	for _, gp := range cr.PrincipalsByDN {
		isMember := slices.ContainsFunc(gp.Members, func(member string) bool { return strings.EqualFold(member, p.DN) })
		if isMember {
			cr.GetAllSidsForDN(gp.DN, src)
		}
	}

	return src.sids
}
