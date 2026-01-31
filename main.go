package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/collector"
	"github.com/jsundin/go-adacl/filters"
	"github.com/jsundin/go-adacl/values"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func run(cmd *cobra.Command, args []string) error {
	if lvl, err := logrus.ParseLevel(appConf.LogLevel); err != nil {
		return err
	} else {
		logrus.SetLevel(lvl)
	}

	var c *collector.Collector
	var err error

	if appConf.CacheFile != "" {
		if _, err = os.Stat(appConf.CacheFile); err == nil {
			if c, err = collector.DeserializeFromFile(appConf.CacheFile); err != nil {
				logrus.Errorf("failed to load collected data from cache file '%s': %s", appConf.CacheFile, err)
				os.Exit(1)
			} else {
				logrus.Infof("loaded collected data from cache file '%s'", appConf.CacheFile)
			}
		}
	}

	if c == nil {
		if c, err = collectInformation(); err != nil {
			logrus.Errorf("%s", err)
			os.Exit(1)
		}
	}

	aces := 0
	for _, v := range c.AcesByDN {
		aces += len(v)
	}
	logrus.Debugf("collected %d dns, %d principals and %d aces", len(c.OrderedDNs), len(c.PrincipalsByDN), aces)

	filterSet := resolveFilters(c)
	logrus.Debugf("resolved %d filters", len(filterSet))

	filtered := 0
	unfiltered := 0

	var jsonOutput *JsonOutput
	if appConf.JsonOutput != "" {
		jsonOutput = &JsonOutput{
			ByObject:  map[string][]*ParsedAce{},
			ByTrustee: map[string][]*ParsedAce{},
		}
	}

	for _, objectDN := range c.OrderedDNs {
		for _, ace := range c.AcesByDN[objectDN] {
			if filterSet.Applies(objectDN, ace) {
				filtered++
				continue
			}
			unfiltered++

			parsedAce := parseAce(c, objectDN, ace)
			if appConf.Stdout {
				parsedAce.Print()
				fmt.Println()
			}

			if jsonOutput != nil {
				jsonOutput.ByObject[parsedAce.DN] = append(jsonOutput.ByObject[parsedAce.DN], parsedAce)
				jsonOutput.ByTrustee[parsedAce.Trustee.Sid] = append(jsonOutput.ByTrustee[parsedAce.Trustee.Sid], parsedAce)
			}
		}
	}
	logrus.Debugf("%d aces processed, and %d were filtered", unfiltered, filtered)

	if appConf.JsonOutput != "" {
		func() {
			f, err := os.Create(appConf.JsonOutput)
			if err != nil {
				logrus.Errorf("could not create json file '%s': %s", appConf.JsonOutput, err)
				return
			}
			defer f.Close()

			if err = json.NewEncoder(f).Encode(jsonOutput); err != nil {
				logrus.Errorf("failed to save json to '%s': %s'", appConf.JsonOutput, err)
			}
		}()
	}

	return nil
}

func collectInformation() (*collector.Collector, error) {
	ldapAddr, err := appConf.GetLdapAddr()
	if err != nil {
		return nil, err
	}

	binder, err := appConf.GetBinder()
	if err != nil {
		return nil, err
	}

	c, err := collector.NewCollector(ldapAddr, binder, appConf.LdapDebug)
	if err != nil {
		return nil, fmt.Errorf("failed to create collector: %s", err)
	}
	defer c.Close()

	if err = c.CollectWhoami(); err != nil {
		return nil, fmt.Errorf("failed to collect whoami: %s", err)
	}

	if err = c.CollectServerConfiguration(); err != nil {
		return nil, fmt.Errorf("failed to collect server configuration: %s", err)
	}

	searchDNs := c.ServerConfiguration.NamingContexts
	if len(appConf.SearchDNs) > 0 {
		searchDNs = appConf.SearchDNs
	}
	if appConf.SearchOnlyDefaultNamingContext {
		searchDNs = []string{c.ServerConfiguration.DefaultNamingContext}
	}

	for _, dn := range searchDNs {
		if err = c.Collect(dn); err != nil {
			return nil, fmt.Errorf("collection of dn '%s' failed: %s", dn, err)
		}
	}

	if appConf.CacheFile != "" {
		if err = c.SerializeToFile(appConf.CacheFile); err != nil {
			logrus.Warnf("failed to save collected data to '%s': %s (proceeding anyway)", appConf.CacheFile, err)
		}
	}

	return c, nil
}

func resolveFilters(c *collector.Collector) filters.FilterSet {
	resolvedIncludeSids := []string{}
	resolvedExcludeSids := []string{}

	if appConf.Filters.IncludeWhoami {
		whoamiPrincipal := strings.Split(c.AuthzId, "\\")[1]
		resolvedIncludeSids = append(resolvedIncludeSids, c.GetAllSidsForPrincipal(whoamiPrincipal, nil)...)
	}

	for _, trustee := range appConf.Filters.IncludeTrustees {
		resolvedIncludeSids = append(resolvedIncludeSids, c.GetAllSidsForPrincipal(trustee, nil)...)
		resolvedIncludeSids = append(resolvedIncludeSids, c.GetAllSidsForSid(trustee, nil)...)
		resolvedIncludeSids = append(resolvedIncludeSids, c.GetAllSidsForDN(trustee, nil)...)
	}

	for _, trustee := range appConf.Filters.ExcludeTrustees {
		if p := c.GetPrincipalBySid(trustee); p != nil {
			resolvedExcludeSids = append(resolvedExcludeSids, p.Sid)
		}
		if p := c.GetPrincipalByName(trustee); p != nil {
			resolvedExcludeSids = append(resolvedExcludeSids, p.Sid)
		}
		if pattern, found := values.GetWellknownSidPatternFromName(trustee); found {
			resolvedExcludeSids = append(resolvedExcludeSids, pattern)
		}
	}

	filterSet := filters.FilterSet{}

	if len(appConf.Filters.IncludeDNs) > 0 {
		filterSet.Add(filters.Include, filters.NewDnMatcherStrings(appConf.Filters.IncludeDNs))
	}

	if len(appConf.Filters.ExcludeDNs) > 0 {
		filterSet.Add(filters.Exclude, filters.NewDnMatcherStrings(appConf.Filters.ExcludeDNs))
	}

	if len(resolvedIncludeSids) > 0 {
		filterSet.Add(filters.Include, filters.NewSidsMatcher(resolvedIncludeSids))
	}

	if len(resolvedExcludeSids) > 0 {
		filterSet.Add(filters.Exclude, filters.NewSidsMatcher(resolvedExcludeSids))
	}

	if appConf.Filters.IncludeInterestingAceTypes {
		filterSet.Add(filters.Include, filters.NewAceTypesMatcher(defaultInterestingAceTypes))
	}

	if appConf.Filters.ExcludeUninterestingTrustees {
		filterSet.Add(filters.Exclude, filters.NewSidsMatcher(defaultUninterestingSidPatterns))
	}

	if appConf.Filters.ExcludeUninterestingDNs {
		filterSet.Add(filters.Exclude, filters.NewRelativeDnMatcher(c.ServerConfiguration.DefaultNamingContext, defaultUninterestingRDNs))
	}

	if appConf.Filters.ExcludeInherited {
		filterSet.Add(filters.Exclude, filters.NewAceFlagsMatcher([]sddlparse.AceFlag{sddlparse.ACEFLAG_INHERITED}))
	}

	if appConf.Filters.IncludeInterestingAccessMasks {
		filterSet.Add(filters.Include, filters.NewAccessMaskMatcher(defaultInterestingAccessMasks))
		filterSet.Add(filters.Exclude, filters.NewEveryoneExtendedRightsMatcher())
	}

	if appConf.Filters.IncludePrincipalTrustees {
		filterSet.Add(filters.Include, filters.NewSidHasPrincipalMatcher(c))
	}

	return filterSet
}
