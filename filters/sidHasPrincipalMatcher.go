package filters

import (
	"github.com/jsundin/go-adacl/collector"
)

type sidHasPrincipalMatcher struct {
	c *collector.Collector
}

func NewSidHasPrincipalMatcher(c *collector.Collector) sidHasPrincipalMatcher {
	return sidHasPrincipalMatcher{c: c}
}

func (m sidHasPrincipalMatcher) matches(dn string, ace *collector.AceEntry) bool {
	p := m.c.GetPrincipalBySid(ace.SID)
	return p != nil
}
