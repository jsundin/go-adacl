package conf

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/jsundin/go-adacl/ldapsupport/binders"
)

type CliConfig struct {
	// misc app stuff
	LogLevel   string
	LdapDebug  bool
	CacheFile  string
	Stdout     bool
	JsonOutput string

	// connection stuff
	Host   string
	Secure bool

	// authentication options
	UseNTLM     bool
	UseKerberos bool
	UseLdapBind bool
	Domain      string
	Username    string
	Password    string
	Hash        string
	SPN         string
	DCHost      string
	CCache      string

	// collection options
	SearchDNs                      []string
	SearchOnlyDefaultNamingContext bool

	Filters struct {
		IncludeDNs              []string // only include objects in these dn:s
		ExcludeDNs              []string // exclude objects in these dn:s
		ExcludeUninterestingDNs bool     // exclude boring dn:s

		IncludeTrustees              []string // only include objects with these trustees
		IncludeWhoami                bool     // only include objects with me as a trustee
		ExcludeUninterestingTrustees bool     // exclude boring trustees (sids)
		ExcludeTrustees              []string // exclude objects with these trustees

		IncludeInterestingAceTypes    bool // only include interesting ace types
		IncludeInterestingAccessMasks bool // only include interesting access masks
		ExcludeInherited              bool // exclude inherited aces
	}
}

func (conf CliConfig) GetLdapAddr() (string, error) {
	var host = conf.Host
	var port = 389
	var scheme = "ldap"

	if host == "" {
		return "", fmt.Errorf("no ldap host provided")
	}

	if conf.Secure {
		port = 636
		scheme = "ldaps"
	}

	if parts := strings.Split(host, ":"); len(parts) == 2 {
		host = parts[0]
		if n, err := strconv.Atoi(parts[1]); err != nil {
			return "", err
		} else {
			port = n
		}
	}

	return fmt.Sprintf("%s://%s:%d", scheme, host, port), nil
}

func (conf CliConfig) GetBinder() (binders.Binder, error) {
	if conf.UseKerberos {
		return conf.getKerberosBinder()
	}

	if conf.Username == "" {
		return binders.NewAnonymousBinder(), nil
	}

	if conf.Username == "" {
		return nil, fmt.Errorf("no username provided")
	}

	if conf.UseLdapBind {
		if conf.Password == "" {
			return nil, fmt.Errorf("no password provided")
		}
		return binders.NewLdapBinder(conf.Username, conf.Password), nil
	}

	if conf.Domain == "" {
		return nil, fmt.Errorf("no domain provided")
	}

	if conf.Hash != "" {
		return binders.NewNtlmHashBinder(conf.Domain, conf.Username, conf.Hash), nil
	}

	if conf.UseNTLM {
		return binders.NewNtlmPasswordBinder(conf.Domain, conf.Username, conf.Password), nil
	}

	return binders.NewADBinder(conf.Domain, conf.Username, conf.Password), nil
}

func (conf CliConfig) getKerberosBinder() (binders.Binder, error) {
	var ldapHostname = conf.Host
	if parts := strings.Split(ldapHostname, ":"); len(parts) == 2 {
		ldapHostname = parts[0]
	}

	if conf.Domain == "" {
		return nil, fmt.Errorf("no domain provided")
	}

	var spn = conf.SPN
	if spn == "" {
		spn = "ldap/" + ldapHostname
	}

	var dchost = conf.DCHost
	if dchost == "" {
		dchost = ldapHostname
	}

	var realm = strings.ToUpper(conf.Domain)

	if conf.Username != "" && conf.Password != "" {
		return binders.NewKerberosPasswordBinder(realm, spn, dchost, conf.Username, conf.Password), nil
	}

	if conf.CCache != "" {
		return binders.NewKerberosCCacheBinder(realm, spn, dchost, conf.CCache), nil
	}

	if krb5ccname := os.Getenv("KRB5CCNAME"); krb5ccname != "" {
		return binders.NewKerberosCCacheBinder(realm, spn, dchost, krb5ccname), nil
	}

	return nil, fmt.Errorf("unable to guess the kerberos authentication options, look at the help")
}
