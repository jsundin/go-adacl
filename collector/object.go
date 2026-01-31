package collector

import (
	"slices"
	"strings"

	"github.com/bwmarrin/go-objectsid"
	"github.com/go-ldap/ldap/v3"
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/ldapsupport"
	"github.com/jsundin/go-adacl/optional"
	"github.com/sirupsen/logrus"
)

func (c *Collector) processObject(ent *ldap.Entry) error {
	c.OrderedDNs = append(c.OrderedDNs, ent.DN)

	var objectSid optional.Optional[string]
	if rawSid := ent.GetRawAttributeValue(ldapsupport.AttrObjectSid); len(rawSid) > 0 {
		objectSid = optional.Of(objectsid.Decode(rawSid).String())
	}

	if len(ent.GetAttributeValues(ldapsupport.AttrSamAccountName)) > 0 {
		p := c.getOrAddPrincipal(ent.DN)
		p.Sid = objectSid.OrElse("missing")
		p.Name = ent.GetAttributeValue(ldapsupport.AttrSamAccountName)

		objectClasses := ent.GetAttributeValues(ldapsupport.AttrObjectClass)
		if slices.Contains(objectClasses, "computer") {
			p.PrincipalType = "computer"
		} else if slices.Contains(objectClasses, "user") {
			p.PrincipalType = "user"
		} else {
			p.PrincipalType = "group"
		}
	}

	if len(ent.GetAttributeValues(ldapsupport.AttrMember)) > 0 {
		c.getOrAddPrincipal(ent.DN).Members = append(c.getOrAddPrincipal(ent.DN).Members, ent.GetAttributeValues(ldapsupport.AttrMember)...)
	}

	if len(ent.GetAttributeValues(ldapsupport.AttrPrimaryGroupID)) > 0 {
		c.getOrAddPrincipal(ent.DN).PrimaryGroupRid = optional.Of(ent.GetAttributeValue(ldapsupport.AttrPrimaryGroupID))
	}

	for _, rawSD := range ent.GetRawAttributeValues(ldapsupport.AttrNTSecurityDescriptor) {
		if sddl, err := sddlparse.SDDLFromBinary(rawSD); err != nil {
			logrus.Warnf("could not parse sddl for: dn='%s'", ent.DN)
		} else {
			for _, ace := range sddl.DACL {
				c.AcesByDN[ent.DN] = append(c.AcesByDN[ent.DN], c.processAce(ace))
			}
		}
	}
	return nil
}

func (c *Collector) processAce(ace *sddlparse.ACE) *AceEntry {
	aceEntry := AceEntry{}
	aceEntry.Type = ace.Type
	aceEntry.Flags = ace.Flags
	aceEntry.AccessMask = ace.AccessMask
	aceEntry.SID = ace.SID
	if !ace.ObjectType.IsNull() {
		aceEntry.ObjectType = optional.Of(ace.ObjectType.String())
	}
	if !ace.InheritedObjectType.IsNull() {
		aceEntry.InheritedObjectType = optional.Of(ace.InheritedObjectType.String())
	}
	return &aceEntry
}

func (c *Collector) getOrAddPrincipal(dn string) *Principal {
	if _, exists := c.PrincipalsByDN[dn]; !exists {
		c.PrincipalsByDN[dn] = &Principal{
			DN: dn,
		}
	}

	return c.PrincipalsByDN[dn]
}

func (cr *Collector) GetPrincipalBySid(sid string) *Principal {
	for _, p := range cr.PrincipalsByDN {
		if strings.EqualFold(p.Sid, sid) {
			return p
		}
	}
	return nil
}

func (c *Collector) GetPrincipalByName(name string) *Principal {
	for _, p := range c.PrincipalsByDN {
		if strings.EqualFold(p.Name, name) {
			return p
		}
	}
	return nil
}
