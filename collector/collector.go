package collector

import (
	"crypto/tls"
	"encoding/json"
	"os"

	"github.com/go-ldap/ldap/v3"
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/ldapsupport/binders"
	"github.com/jsundin/go-adacl/optional"
	"github.com/sirupsen/logrus"
)

type Collector struct {
	conn *ldap.Conn

	ServerAddr          string
	AuthzId             string
	ServerConfiguration ServerConfiguration

	OrderedDNs     []string
	PrincipalsByDN map[string]*Principal
	AcesByDN       map[string][]*AceEntry
}

type ServerConfiguration struct {
	DefaultNamingContext string
	NamingContexts       []string
}

type Principal struct {
	DN              string
	Sid             string
	Name            string
	PrincipalType   string
	Members         []string
	PrimaryGroupRid optional.Optional[string]
}

type AceEntry struct {
	Type                sddlparse.AceType
	Flags               sddlparse.AceFlag
	AccessMask          sddlparse.AccessMask
	SID                 string
	ObjectType          optional.Optional[string]
	InheritedObjectType optional.Optional[string]
}

func NewCollector(ldapAddr string, binder binders.Binder, ldapDebug bool) (*Collector, error) {
	logrus.Debugf("attempting to dial ldap '%s'", ldapAddr)
	conn, err := ldap.DialURL(ldapAddr, ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		return nil, err
	}
	if ldapDebug {
		conn.Debug = true
	}

	if err = binder.Bind(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return &Collector{
		conn:       conn,
		ServerAddr: ldapAddr,

		PrincipalsByDN: map[string]*Principal{},
		AcesByDN:       map[string][]*AceEntry{},
	}, nil
}

func (c *Collector) Close() error {
	return c.conn.Close()
}

func (c *Collector) SerializeToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	return json.NewEncoder(f).Encode(c)
}

func DeserializeFromFile(filename string) (*Collector, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	c := Collector{}

	if err := json.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}

	return &c, nil
}
