package binders

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
)

type ldapBinder struct {
	dn       string
	password string
}

type adBinder struct {
	domain   string
	username string
	password string
}

func NewLdapBinder(dn string, password string) Binder {
	return &ldapBinder{
		dn:       dn,
		password: password,
	}
}

func NewADBinder(domain string, username string, password string) Binder {
	return &adBinder{
		domain:   domain,
		username: username,
		password: password,
	}
}

func (b *ldapBinder) Bind(conn *ldap.Conn) error {
	logrus.Debugf("binding using ldap credentials: dn='%s', password='%s'", b.dn, b.password)
	return conn.Bind(b.dn, b.password)
}

func (b *adBinder) Bind(conn *ldap.Conn) error {
	bindUsername := fmt.Sprintf("%s@%s", b.username, b.domain)
	logrus.Debugf("binding using ad credentials: username='%s', password='%s'", bindUsername, b.password)
	return conn.Bind(bindUsername, b.password)
}
