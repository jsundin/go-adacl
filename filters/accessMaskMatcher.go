package filters

import (
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/collector"
)

type accessMaskMatcher struct {
	accessMasks []sddlparse.AccessMask
}

func NewAccessMaskMatcher(accessMasks []sddlparse.AccessMask) accessMaskMatcher {
	return accessMaskMatcher{
		accessMasks: accessMasks,
	}
}

func (m accessMaskMatcher) matches(dn string, ace *collector.AceEntry) bool {
	for _, v := range m.accessMasks {
		if ace.AccessMask&v == v {
			return true
		}
	}
	return false
}
