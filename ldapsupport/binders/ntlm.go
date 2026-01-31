package binders

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
)

type ntlmPasswordBinder struct {
	domain   string
	username string
	password string
}

type ntlmHashBinder struct {
	domain   string
	username string
	hash     string
}

func NewNtlmPasswordBinder(domain string, username string, password string) Binder {
	return nil
}

func NewNtlmHashBinder(domain string, username string, hash string) Binder {
	return &ntlmHashBinder{
		domain:   domain,
		username: username,
		hash:     hash,
	}
}

func (b *ntlmPasswordBinder) Bind(conn *ldap.Conn) error {
	logrus.Debugf("binding using ntlm credentials: domain='%s', username='%s', password='%s'", b.domain, b.username, b.password)
	return conn.NTLMBind(b.domain, b.username, b.password)
}

func (b *ntlmHashBinder) Bind(conn *ldap.Conn) error {
	logrus.Debugf("binding using ntlm hash credentials: domain='%s', username='%s', hash='%s'", b.domain, b.username, b.hash)
	return conn.NTLMBindWithHash(b.domain, b.username, b.hash)
}
