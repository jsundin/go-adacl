package values

import (
	"github.com/huner2/go-sddlparse/v2"
)

const (
	ACCESS_MASK_FULL_CONTROL     = sddlparse.AccessMask(0xf01ff)
	ACCESS_MASK_MODIFY           = sddlparse.AccessMask(0x0301bf)
	ACCESS_MASK_READ_AND_EXECUTE = sddlparse.AccessMask(0x0200a9)
	ACCESS_MASK_READ_AND_WRITE   = sddlparse.AccessMask(0x02019f)
	ACCESS_MASK_READ             = sddlparse.AccessMask(0x20094)
	ACCESS_MASK_WRITE            = sddlparse.AccessMask(0x200bc)
)

func AccessMaskToString(mask sddlparse.AccessMask) []string {
	arr := []string{}
	for v, label := range usefulAccessMasksDef {
		if mask&v == v {
			mask = mask & (^v)
			arr = append(arr, label)
		}
	}
	for v, label := range rawAccessMasksDef {
		if mask&v == v {
			mask = mask & (^v)
			arr = append(arr, label)
		}
	}

	arr2 := []string{}
	for _, v := range arr {
		if translated, found := prettyAccessMasksTranslations[v]; found {
			arr2 = append(arr2, translated)
		} else {
			arr2 = append(arr2, v)
		}
	}
	return arr2
}

var rawAccessMasksDef = map[sddlparse.AccessMask]string{
	sddlparse.ACCESS_MASK_GENERIC_READ:                "GENERIC_READ",
	sddlparse.ACCESS_MASK_GENERIC_WRITE:               "GENERIC_WRITE",
	sddlparse.ACCESS_MASK_GENERIC_EXECUTE:             "GENERIC_EXECUTE",
	sddlparse.ACCESS_MASK_GENERIC_ALL:                 "GENERIC_ALL",
	sddlparse.ACCESS_MASK_MAXIMUM_ALLOWED:             "MAXIMUM_ALLOWED",
	sddlparse.ACCESS_MASK_ACCESS_SYSTEM_SECURITY:      "ACCESS_SYSTEM_SECURITY",
	sddlparse.ACCESS_MASK_SYNCHRONIZE:                 "SYNCHRONIZE",
	sddlparse.ACCESS_MASK_WRITE_OWNER:                 "WRITE_OWNER",
	sddlparse.ACCESS_MASK_WRITE_DACL:                  "WRITE_DACL",
	sddlparse.ACCESS_MASK_READ_CONTROL:                "READ_CONTROL",
	sddlparse.ACCESS_MASK_DELETE:                      "DELETE",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_CREATE_CHILD:   "ADS_RIGHT_DS_CREATE_CHILD",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_DELETE_CHILD:   "ADS_RIGHT_DS_DELETE_CHILD",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_LIST_CONTENTS:  "ADS_RIGHT_DS_LIST_CONTENTS",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_SELF:           "ADS_RIGHT_DS_SELF",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_READ_PROP:      "ADS_RIGHT_DS_READ_PROP",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_WRITE_PROP:     "ADS_RIGHT_DS_WRITE_PROP",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_DELETE_TREE:    "ADS_RIGHT_DS_DELETE_TREE",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_LIST_OBJECT:    "ADS_RIGHT_DS_LIST_OBJECT",
	sddlparse.ACCESS_MASK_ADS_RIGHT_DS_CONTROL_ACCESS: "ADS_RIGHT_DS_CONTROL_ACCESS",
}

var usefulAccessMasksDef = map[sddlparse.AccessMask]string{
	0xffffffff: "*",

	// dacledit.py
	ACCESS_MASK_FULL_CONTROL:     "FullControl",
	ACCESS_MASK_MODIFY:           "Modify",
	ACCESS_MASK_READ_AND_EXECUTE: "ReadAndExecute",
	ACCESS_MASK_READ_AND_WRITE:   "ReadAndWrite",
	ACCESS_MASK_READ:             "Read",
	ACCESS_MASK_WRITE:            "Write",
}

var prettyAccessMasksTranslations = map[string]string{
	"GENERIC_READ":                "GenericRead",
	"GENERIC_WRITE":               "GenericWrite",
	"GENERIC_EXECUTE":             "GenericExecute",
	"GENERIC_ALL":                 "GenericAll",
	"MAXIMUM_ALLOWED":             "MaximumAllowed",
	"ACCESS_SYSTEM_SECURITY":      "AccessSystemSecurity",
	"SYNCHRONIZE":                 "Synchronize",
	"WRITE_OWNER":                 "WriteOwner",
	"WRITE_DACL":                  "WriteDacl",
	"READ_CONTROL":                "ReadControl",
	"DELETE":                      "Delete",
	"ADS_RIGHT_DS_CREATE_CHILD":   "CreateChild",
	"ADS_RIGHT_DS_DELETE_CHILD":   "DeleteChild",
	"ADS_RIGHT_DS_LIST_CONTENTS":  "ListContents",
	"ADS_RIGHT_DS_SELF":           "Self",
	"ADS_RIGHT_DS_READ_PROP":      "ReadProp",
	"ADS_RIGHT_DS_WRITE_PROP":     "WriteProp",
	"ADS_RIGHT_DS_DELETE_TREE":    "DeleteTree",
	"ADS_RIGHT_DS_LIST_OBJECT":    "ListObject",
	"ADS_RIGHT_DS_CONTROL_ACCESS": "ControlAccess",
}
