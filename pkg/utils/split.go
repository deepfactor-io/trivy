package utils

import (
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/types"
	"github.com/samber/lo"
)

var typesForPkgSplit = []ftypes.TargetType{ftypes.NodePkg, ftypes.Yarn, ftypes.Npm, ftypes.Pnpm}

func IsPkgSplitRequired(targetType ftypes.TargetType) bool {
	return lo.Contains(typesForPkgSplit, targetType)
}

func SplitDirectDepsVuln(results []types.Result) []types.Result {
	for i, result := range results {
		if IsPkgSplitRequired(result.Type) {
			for i, vuln := range result.Vulnerabilities {
				if !vuln.PkgIndirect && len(vuln.PkgRootDependencies) > 0 {
					// is both direct and indirect
					// add new entry for indirect
					indirectVuln := vuln
					indirectVuln.PkgIndirect = true
					result.Vulnerabilities = append(result.Vulnerabilities, indirectVuln)

					// set [] root dep for direct dep
					result.Vulnerabilities[i].PkgRootDependencies = []string{}
				}
			}
		}

		results[i] = result
	}

	return results
}
