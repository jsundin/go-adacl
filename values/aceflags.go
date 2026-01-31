package values

import "github.com/huner2/go-sddlparse/v2"

func AceFlagsToString(aceFlags sddlparse.AceFlag) []string {
	arr := []string{}
	for v, label := range aceFlagsDef {
		if aceFlags&v == v {
			arr = append(arr, label)
		}
	}
	return arr
}

var aceFlagsDef = map[sddlparse.AceFlag]string{
	sddlparse.ACEFLAG_OBJECT_INHERIT:       "OBJECT_INHERIT",
	sddlparse.ACEFLAG_CONTAINER_INHERIT:    "CONTAINER_INHERIT",
	sddlparse.ACEFLAG_NO_PROPAGATE_INHERIT: "NO_PROPAGATE_INHERIT",
	sddlparse.ACEFLAG_INHERIT_ONLY:         "INHERIT_ONLY",
	sddlparse.ACEFLAG_INHERITED:            "INHERITED",
	sddlparse.ACEFLAG_SUCCESSFUL_ACCESS:    "SUCCESSFUL_ACCESS",
	sddlparse.ACEFLAG_FAILED_ACCESS:        "FAILED_ACCESS",
}
