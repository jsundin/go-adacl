package collector

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"
	"github.com/jsundin/go-adacl/ldapsupport"
	"github.com/sirupsen/logrus"
)

func (c *Collector) CollectWhoami() error {
	whoami, err := c.conn.WhoAmI([]ldap.Control{})
	if err != nil {
		return err
	}
	c.AuthzId = whoami.AuthzID
	logrus.Debugf("collected whoami: '%s'", c.AuthzId)
	return nil
}

func (c *Collector) CollectServerConfiguration() error {
	res, err := c.conn.Search(&ldap.SearchRequest{
		BaseDN:       "",
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
		Attributes: []string{
			ldapsupport.AttrDefaultNamingContext,
			ldapsupport.AttrNamingContexts,
		},
	})
	if err != nil {
		return err
	}

	if len(res.Entries) != 1 {
		return fmt.Errorf("server configuration contained %d entries, expected exactly one", len(res.Entries))
	}

	c.ServerConfiguration = ServerConfiguration{
		DefaultNamingContext: res.Entries[0].GetAttributeValue(ldapsupport.AttrDefaultNamingContext),
		NamingContexts:       res.Entries[0].GetAttributeValues(ldapsupport.AttrNamingContexts),
	}

	logrus.Debugf("collected server configuration: defaultNamingContext='%s', namingContexts='[%v]", c.ServerConfiguration.DefaultNamingContext, c.ServerConfiguration.NamingContexts)
	return nil
}

func (c *Collector) Collect(dn string) error {
	logrus.Debugf("collecting information from: dn='%s'", dn)

	sdFlagsCtrl := &ldap.ControlMicrosoftSDFlags{
		Criticality:  true,
		ControlValue: ldapsupport.SDFLAGS_DACL_SECURITY_INFORMATION,
	}

	pagingCtrl := ldap.NewControlPaging(ldapsupport.LDAP_PAGING_SIZE)

	req := &ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Filter:       "(objectClass=*)",
		Attributes:   []string{ldapsupport.AttrObjectSid, ldapsupport.AttrSamAccountName, ldapsupport.AttrMember, ldapsupport.AttrPrimaryGroupID, ldapsupport.AttrObjectClass, ldapsupport.AttrNTSecurityDescriptor, ldapsupport.AttrGroupMSAMembership},
		Controls:     []ldap.Control{sdFlagsCtrl, pagingCtrl},
	}

	for {
		res, err := c.conn.Search(req)
		if err != nil {
			return err
		}

		for _, ent := range res.Entries {
			if err = c.processObject(ent); err != nil {
				return err
			}
		}

		pagingCtrlRes := ldap.FindControl(res.Controls, ldap.ControlTypePaging)
		if pagingCtrlRes == nil {
			logrus.Warnf("no paging support (which is weird and unusual)")
			break
		}

		cookie := pagingCtrlRes.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			break
		}

		pagingCtrl.SetCookie(cookie)
	}
	return nil
}
