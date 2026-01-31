package main

import (
	"os"

	"github.com/google/shlex"
	"github.com/jsundin/go-adacl/conf"
	"github.com/spf13/cobra"
)

var appConf conf.CliConfig

var rootCmd = &cobra.Command{
	Use:   "go-adacl",
	Short: "AD ACL enumeration",
	RunE:  run,
}

func init() {
	if opts := os.Getenv("ADACL_OPTS"); opts != "" {
		parts, err := shlex.Split(opts)
		if err != nil {
			panic(err)
		}
		rootCmd.SetArgs(parts)
	}
	f := rootCmd.Flags()
	f.SortFlags = false

	f.BoolVarP(&appConf.Secure, "secure", "s", false, "use ldaps instead of ldap")
	f.StringVar(&appConf.Host, "host", "", "ldap server with optional port (eg dc.mydomain.local or 10.0.0.10, or 10.0.0.10:389)")

	f.StringVarP(&appConf.Domain, "domain", "d", "", "domain")
	f.StringVarP(&appConf.Username, "username", "u", "", "username")
	f.StringVarP(&appConf.Password, "password", "p", "", "password")
	f.StringVarP(&appConf.Hash, "pth", "H", "", "authenticate using a hash")
	f.BoolVarP(&appConf.UseKerberos, "kerberos", "k", false, "use kerberos (username/password if specified, ccache if specified or KRB5CCNAME environment variable if set)")
	f.BoolVar(&appConf.UseNTLM, "ntlm", false, "username/password authentication using ntlm")
	f.StringVar(&appConf.SPN, "spn", "", "ldap spn for kerberos (eg ldap/dc.mydomain.local), will default to 'ldap/' and the host argument")
	f.StringVar(&appConf.DCHost, "dc-host", "", "kdc hostname or ip, will default to host argument")
	f.StringVar(&appConf.CCache, "ccache", "", "ccache for kerberos (either a filename, or a base64 encoded hash)")
	f.BoolVar(&appConf.UseLdapBind, "ldap-bind", false, "perform a ldap bind (eg username will be the dn instead of an actual username)")

	f.StringArrayVar(&appConf.SearchDNs, "search-dn", []string{}, "list of dns to collect from")
	f.BoolVar(&appConf.SearchOnlyDefaultNamingContext, "search-only-default-dn", false, "collect only from default dn")

	f.StringArrayVar(&appConf.Filters.ExcludeDNs, "exclude-dns", []string{}, "exclude objects living in these dn:s")
	f.StringArrayVar(&appConf.Filters.IncludeDNs, "include-dns", []string{}, "include only objects living in these dn:s")
	f.BoolVar(&appConf.Filters.ExcludeUninterestingDNs, "exclude-uninteresting-dns", true, "exclude uninteresting dn:s")

	f.StringArrayVar(&appConf.Filters.IncludeTrustees, "include-trustee", []string{}, "include only objects with these trustees (dn, sid or principal) (will resolve groups)")
	f.BoolVarP(&appConf.Filters.IncludeWhoami, "include-me", "I", false, "if set, the results from 'whoami' will be added to '--include-trustee'")
	f.BoolVar(&appConf.Filters.ExcludeUninterestingTrustees, "exclude-uninteresting-trustees", true, "exclude boring trustees")
	f.StringSliceVar(&appConf.Filters.ExcludeTrustees, "exclude-trustee", []string{}, "exclude trustees (sid or principal) (will *not* resolve groups)")
	f.BoolVar(&appConf.Filters.IncludePrincipalTrustees, "include-principals", false, "only include objects where the trustee is a principal")

	f.BoolVar(&appConf.Filters.IncludeInterestingAceTypes, "include-interesting-ace-types", true, "only include interesting ace types")
	f.BoolVar(&appConf.Filters.IncludeInterestingAccessMasks, "include-interesting-accessmasks", true, "only include interesting access masks")
	f.BoolVar(&appConf.Filters.ExcludeInherited, "exclude-inherited", false, "exclude inherited aces")

	f.BoolVar(&appConf.Stdout, "stdout", true, "print results to stdout")
	f.StringVar(&appConf.JsonOutput, "json", "", "write results to a json file")
	f.StringVar(&appConf.CacheFile, "cache", "", "cache file")
	f.StringVar(&appConf.LogLevel, "loglevel", "info", "log level (see logrus for details)")
	f.BoolVar(&appConf.LdapDebug, "debug", false, "print ldap debug information (this does not imply --loglevel debug)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
