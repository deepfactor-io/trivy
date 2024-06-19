package utils

import (
	"strings"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/samber/lo"
)

// target type for which we will split pkg which is both indirect and direct
var typesForPkgSplit = []ftypes.TargetType{ftypes.NodePkg, ftypes.Yarn, ftypes.Npm, ftypes.Pnpm}

func IsPkgSplitRequired(targetType ftypes.TargetType) bool {
	return lo.Contains(typesForPkgSplit, targetType)
}

// Function parses the given license name.
// If it's a single license, return it.
// If it's combination of licenses, split it based on the seperators and return it
func SplitNGetLicenses(license string) []string {
	// common separators present in license name
	separators := []string{" OR ", " AND "}

	// Trim parentheses
	license = strings.Trim(license, "()")

	// Check if the string contains any separators
	containsSeparator := false
	for _, separator := range separators {
		if strings.Contains(license, separator) {
			containsSeparator = true
			break
		}
	}

	// If no separator is found, return the whole string as a single license
	if !containsSeparator {
		return []string{license}
	}

	// Split the string by each separator without keeping the separators
	parts := []string{license}
	for _, separator := range separators {
		tempParts := []string{}
		for _, part := range parts {
			tempParts = append(tempParts, strings.Split(part, separator)...)
		}
		parts = tempParts
	}

	// Clean up the parts by trimming whitespace and filtering out empty strings
	var cleanedParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			cleanedParts = append(cleanedParts, part)
		}
	}

	return lo.Uniq(cleanedParts)
}
