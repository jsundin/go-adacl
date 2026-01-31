package main

import (
	"github.com/huner2/go-sddlparse/v2"
	"github.com/jsundin/go-adacl/values"
)

var defaultInterestingAccessMasks = []sddlparse.AccessMask{
	values.ACCESS_MASK_FULL_CONTROL,
	values.ACCESS_MASK_MODIFY,
	values.ACCESS_MASK_READ_AND_EXECUTE,
	values.ACCESS_MASK_READ_AND_WRITE,
	values.ACCESS_MASK_WRITE,

	sddlparse.ACCESS_MASK_GENERIC_WRITE,
	sddlparse.ACCESS_MASK_GENERIC_ALL,
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_CREATE_CHILD,
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP,
	sddlparse.ACCESS_MASK_WRITE_DACL,
	sddlparse.ACCESS_MASK_WRITE_OWNER,
}

var defaultInterestingAceTypes = []sddlparse.AceType{
	sddlparse.ACETYPE_ACCESS_ALLOWED,
	sddlparse.ACETYPE_ACCESS_ALLOWED_OBJECT,
	sddlparse.ACETYPE_ACCESS_DENIED,
	sddlparse.ACETYPE_ACCESS_DENIED_OBJECT,
}

var defaultUninterestingRDNs = []string{
	"DC=RootDNSServers,CN=MicrosoftDNS,CN=System",
	"CN=DFSR-LocalSettings,CN=DC,OU=Domain Controllers",
	"DC=RootDNSServers,CN=MicrosoftDNS,DC=DomainDnsZones",
}

var defaultUninterestingSidPatterns = []string{
	"*-512",        // Domain Admins
	"*-516",        // Domain Controllers
	"*-517",        // Cert Publishers
	"*-519",        // Enterprise Admins
	"*-518",        // Schema Admins
	"*-519",        // Enterprise Admins
	"*-520",        //  Group Policy Creator Owners
	"*-522",        // DS-Clone-Domain-Controller
	"*-526",        // Key Admins
	"*-527",        // Enterprise Key Admins
	"*-553",        // RAS and IAS Servers
	"S-1-5-9",      // Enterprise Domain Controllers
	"S-1-5-10",     // Principal Self
	"S-1-5-18",     // Local System
	"S-1-5-32-544", // Administrators
	"S-1-5-32-548", // Account Operators
	"S-1-5-32-550", // Print Operators
	"S-1-5-32-554", // BUILTIN\Pre-Windows 2000 Compatible Access
	"S-1-5-32-560", // BUILTIN\Windows Authorization Access Group
	"S-1-5-32-561", // BUILTIN\Terminal Server License Servers
}
