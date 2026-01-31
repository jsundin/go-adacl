package main

import (
	"fmt"
	"strings"

	"github.com/jsundin/go-adacl/collector"
	"github.com/jsundin/go-adacl/optional"
	"github.com/jsundin/go-adacl/values"
)

type JsonOutput struct {
	ByObject  map[string][]*ParsedAce `json:"byObject"`
	ByTrustee map[string][]*ParsedAce `json:"byTrustee"`
}

type ParsedObject struct {
	ObjectType string                    `json:"type"`
	Name       optional.Optional[string] `json:"name"`
}

type ParsedAce struct {
	DN          string                    `json:"dn"`
	DNType      optional.Optional[string] `json:"dnType"`
	DNPrincipal optional.Optional[string] `json:"dnPrincipal"`
	AceType     string                    `json:"aceType"`
	AceFlags    []string                  `json:"aceFlags"`
	AccessMask  []string                  `json:"accessMask"`
	Trustee     struct {
		Sid           string                    `json:"sid"`
		Principal     optional.Optional[string] `json:"principal"`
		PrincipalType optional.Optional[string] `json:"type"`
	} `json:"trustee"`
	Object          optional.Optional[ParsedObject] `json:"object"`
	InheritedObject optional.Optional[ParsedObject] `json:"inheritedObject"`
}

func parseAce(c *collector.Collector, objectDN string, ace *collector.AceEntry) *ParsedAce {
	pAce := ParsedAce{
		DN: objectDN,
	}

	if principal, exists := c.PrincipalsByDN[objectDN]; exists {
		pAce.DNType = optional.Of(principal.PrincipalType)
		pAce.DNPrincipal = optional.Of(principal.Name)
	}
	pAce.AceType, _ = values.AceTypeToString(ace.Type)
	pAce.AceFlags = values.AceFlagsToString(ace.Flags)
	pAce.AccessMask = values.AccessMaskToString(ace.AccessMask)

	pAce.Trustee.Sid = ace.SID
	if resolved, found := values.GetWellknownSid(ace.SID); found {
		pAce.Trustee.Principal = optional.Of(resolved)
	} else if principal := c.GetPrincipalBySid(ace.SID); principal != nil {
		pAce.Trustee.Principal = optional.Of(principal.Name)
		pAce.Trustee.PrincipalType = optional.Of(principal.PrincipalType)
	}

	ace.ObjectType.IfPresent(func(value string) {
		var name optional.Optional[string]
		if resolved, found := values.ResolveWellknownObjectType(value); found {
			name = optional.Of(resolved)
		}

		pAce.Object = optional.Of(ParsedObject{
			ObjectType: value,
			Name:       name,
		})
	})

	ace.InheritedObjectType.IfPresent(func(value string) {
		var name optional.Optional[string]
		if resolved, found := values.ResolveWellknownObjectType(value); found {
			name = optional.Of(resolved)
		}

		pAce.InheritedObject = optional.Of(ParsedObject{
			ObjectType: value,
			Name:       name,
		})
	})

	return &pAce
}

func (pAce *ParsedAce) Print() {
	dnType := ""
	dnTypeData := []string{}
	pAce.DNType.IfPresent(func(value string) { dnTypeData = append(dnTypeData, value) })
	pAce.DNPrincipal.IfPresent(func(value string) { dnTypeData = append(dnTypeData, value) })
	if len(dnTypeData) > 0 {
		dnType = " (" + strings.Join(dnTypeData, ": ") + ")"
	}

	trusteeType := ""
	trusteeTypeData := []string{}
	pAce.Trustee.PrincipalType.IfPresent(func(value string) { trusteeTypeData = append(trusteeTypeData, value) })
	pAce.Trustee.Principal.IfPresent(func(value string) { trusteeTypeData = append(trusteeTypeData, value) })
	trusteeType = " (" + strings.Join(trusteeTypeData, ": ") + ")"

	fmt.Printf("- %s%s\n", pAce.DN, dnType)
	fmt.Printf("  ACEType:               %s\n", pAce.AceType)
	if len(pAce.AceFlags) > 0 {
		fmt.Printf("  ACEFlags:              %s\n", strings.Join(pAce.AceFlags, ", "))
	}
	if len(pAce.AccessMask) > 0 {
		fmt.Printf("  AccessMask:            %s\n", strings.Join(pAce.AccessMask, ", "))
	}
	fmt.Printf("  SecurityIdentifier:    %s%s\n", pAce.Trustee.Sid, trusteeType)
	pAce.Object.IfPresent(func(value ParsedObject) {
		fmt.Printf("  Object type:           %s\n", value.Name.OrElse(value.ObjectType))
	})
	pAce.InheritedObject.IfPresent(func(value ParsedObject) {
		fmt.Printf("  Inherited object type: %s\n", value.Name.OrElse(value.ObjectType))
	})
}
