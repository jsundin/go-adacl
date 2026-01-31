package filters

import "github.com/jsundin/go-adacl/collector"

type FilterType int

const (
	Include FilterType = 1
	Exclude FilterType = 2
)

type Matcher interface {
	matches(dn string, ace *collector.AceEntry) bool
}

type filter struct {
	filterType FilterType
	matcher    Matcher
}

type FilterSet []filter

func (fs *FilterSet) Add(filterType FilterType, matcher Matcher) {
	*fs = append(*fs, filter{filterType: filterType, matcher: matcher})
}

func (fs FilterSet) Applies(dn string, ace *collector.AceEntry) bool {
	for _, filter := range fs {
		m := filter.matcher.matches(dn, ace)
		if filter.filterType == Include && !m {
			return true
		}
		if filter.filterType == Exclude && m {
			return true
		}
	}
	return false
}
