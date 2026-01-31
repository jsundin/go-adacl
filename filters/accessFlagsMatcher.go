package filters

import (
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/collector"
)

type aceFlagsMatcher struct {
	aceFlags []sddlparse.AceFlag
}

func NewAceFlagsMatcher(aceFlags []sddlparse.AceFlag) aceFlagsMatcher {
	return aceFlagsMatcher{
		aceFlags: aceFlags,
	}
}

func (m aceFlagsMatcher) matches(dn string, ace *collector.AceEntry) bool {
	for _, f := range m.aceFlags {
		if f&ace.Flags == f {
			return true
		}
	}
	return false
}
