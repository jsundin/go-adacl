package filters

import (
	"slices"

	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/collector"
)

type aceTypesMatcher struct {
	aceTypes []sddlparse.AceType
}

func NewAceTypesMatcher(aceTypes []sddlparse.AceType) aceTypesMatcher {
	return aceTypesMatcher{
		aceTypes: aceTypes,
	}
}

func (m aceTypesMatcher) matches(dn string, ace *collector.AceEntry) bool {
	return slices.Contains(m.aceTypes, ace.Type)
}
