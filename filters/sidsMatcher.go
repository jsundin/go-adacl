package filters

import (
	"path/filepath"

	"github.com/jsundin/go-adacl/collector"
)

type sidsMatcher struct {
	sidPatterns []string
}

func NewSidsMatcher(sidPatterns []string) sidsMatcher {
	return sidsMatcher{
		sidPatterns: sidPatterns,
	}
}

func (m sidsMatcher) matches(dn string, ace *collector.AceEntry) bool {
	for _, pattern := range m.sidPatterns {
		if m, _ := filepath.Match(pattern, ace.SID); m {
			return true
		}
	}
	return false
}
