package parser

import (
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveLength(property *Property) (*Property, bool) {
	if !property.isFunction() {
		return property, true
	}

	val := property.AsMap()["Fn::Length"]
	if val.IsList() {
		return property.deriveResolved(cftypes.Int, val.Len()), true
	} else if val.IsMap() {
		resolved, _ := val.resolveValue()

		if resolved.IsList() {
			return property.deriveResolved(cftypes.Int, resolved.Len()), true
		}
		return resolved, false
	}

	return property, false

}
