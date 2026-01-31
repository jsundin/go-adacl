package filters

import (
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/collector"
	"github.com/jsundin/go-adacl/values"
)

type everyoneExtendedRightsMatcher struct{}

func NewEveryoneExtendedRightsMatcher() everyoneExtendedRightsMatcher {
	return everyoneExtendedRightsMatcher{}
}

func (m everyoneExtendedRightsMatcher) matches(dn string, ace *collector.AceEntry) bool {
	if ace.AccessMask == sddlparse.ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS {
		if ace.SID == values.WellknownSidAuthenticatedUsers || ace.SID == values.WellknownSidEveryone {
			return true
		}
	}
	return false
}
