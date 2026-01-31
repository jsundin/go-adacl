package binders

import "github.com/go-ldap/ldap/v3"

type Binder interface {
	Bind(conn *ldap.Conn) error
}

type anonymousBinder struct{}

func NewAnonymousBinder() Binder {
	return &anonymousBinder{}
}

func (b *anonymousBinder) Bind(conn *ldap.Conn) error {
	return nil
}
