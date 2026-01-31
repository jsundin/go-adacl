package binders

import (
	"encoding/base64"
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldap/v3/gssapi"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/sirupsen/logrus"
)

type kerberosBinder struct {
	realm  string
	spn    string
	dchost string
}

type kerberosPasswordBinder struct {
	kerberosBinder
	username string
	password string
}

type kerberosCCacheBinder struct {
	kerberosBinder
	ccache string
}

func NewKerberosPasswordBinder(realm string, spn string, dchost string, username string, password string) Binder {
	return &kerberosPasswordBinder{
		kerberosBinder: kerberosBinder{
			realm:  realm,
			spn:    spn,
			dchost: dchost,
		},
		username: username,
		password: password,
	}
}

func NewKerberosCCacheBinder(realm string, spn string, dchost string, ccache string) Binder {
	return &kerberosCCacheBinder{
		kerberosBinder: kerberosBinder{
			realm:  realm,
			spn:    spn,
			dchost: dchost,
		},
		ccache: ccache,
	}
}

func (b *kerberosPasswordBinder) Bind(conn *ldap.Conn) error {
	logrus.Debugf("binding using kerberos credentials: realm='%s', spn='%s', dchost='%s', username='%s', password='%s'", b.realm, b.spn, b.dchost, b.username, b.password)
	krb5Conf := b.getKrb5Conf()
	krb5Client := client.NewWithPassword(b.username, b.realm, b.password, krb5Conf, client.DisablePAFXFAST(true))

	return b.performBind(conn, krb5Client)
}

func (b *kerberosCCacheBinder) Bind(conn *ldap.Conn) error {
	krb5Conf := b.getKrb5Conf()

	var ccache *credentials.CCache
	var err error

	if raw, err := base64.StdEncoding.DecodeString(b.ccache); err == nil {
		logrus.Debugf("ccache is valid base64, attempting to decode")
		tmp := new(credentials.CCache)
		if err = tmp.Unmarshal(raw); err == nil {
			logrus.Debugf("successfully base64 decoded ccache")
			ccache = tmp
		}
	}

	if ccache == nil {
		logrus.Debugf("attempting to load ccache from file '%s'", b.ccache)
		if ccache, err = credentials.LoadCCache(b.ccache); err != nil {
			return err
		}
	}

	logrus.Debugf("parsed ccache: realm='%s', principal='%s'", ccache.GetClientRealm(), ccache.GetClientPrincipalName().PrincipalNameString())

	krb5Client, err := client.NewFromCCache(ccache, krb5Conf, client.DisablePAFXFAST(true))
	if err != nil {
		return err
	}

	return b.performBind(conn, krb5Client)
}

func (k kerberosBinder) getKrb5Conf() *config.Config {
	krb5Conf := config.New()
	krb5Conf.Realms = append(krb5Conf.Realms, config.Realm{
		Realm: k.realm,
		KDC:   []string{fmt.Sprintf("%s:88", k.dchost)},
	})
	return krb5Conf
}

func (k kerberosBinder) performBind(conn *ldap.Conn, krb5Client *client.Client) error {
	gssapiClient := gssapi.Client{
		Client: krb5Client,
	}

	bindRequest := ldap.GSSAPIBindRequest{
		ServicePrincipalName: k.spn,
		AuthZID:              "",
	}

	return conn.GSSAPIBindRequestWithAPOptions(&gssapiClient, &bindRequest, []int{flags.APOptionMutualRequired}) // https://github.com/go-ldap/ldap/issues/536
}
