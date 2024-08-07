package utils

import (
	"strings"

	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/github/go-spdx/v2/spdxexp"
	"github.com/samber/lo"
)

// target type for which we will split pkg which is both indirect and direct
var typesForPkgSplit = []ftypes.TargetType{ftypes.NodePkg, ftypes.Yarn, ftypes.Npm, ftypes.Pnpm}

func IsPkgSplitRequired(targetType ftypes.TargetType) bool {
	return lo.Contains(typesForPkgSplit, targetType)
}

// Func splits the given licenses (if any separators like AND/OR are present in the license),
// validates those individual licenses if they are SPDX defined or not.
// If any SPDX license is found, it filters those licenses and returns them.
// else we just return the given input license string
func FilterNGetLicenses(licenses []string) []string {
	var foundSPDXLicense bool
	var result []string
	var tempLicenses []string

	// Split and validate licenses
	for _, license := range licenses {
		// skip empty licenses
		if len(license) == 0 {
			continue
		}
		tempLicenses = append(tempLicenses, license)

		for _, license := range splitLicense(license) {
			ok, _ := spdxexp.ValidateLicenses([]string{license})
			foundSPDXLicense = foundSPDXLicense || ok

			if ok {
				result = append(result, license)
			}
		}
	}
	licenses = tempLicenses

	if !foundSPDXLicense {
		return lo.Uniq(licenses)
	}

	// distinct license names will be returned
	return lo.Uniq(result)
}

// Func parses the given license name.
// If it's a single license, return it. If it's combination of licenses, split it based on the seperators and return it
func splitLicense(license string) []string {
	// common separators present in license name
	separators := []string{" OR ", " AND "}

	// Trim parentheses
	license = strings.Trim(license, "()[]")

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
		part = strings.Trim(part, "()[]")
		if part != "" {
			cleanedParts = append(cleanedParts, part)
		}
	}

	return lo.Uniq(cleanedParts)
}

// validate whether given license is SPDX defined or not
func ValidateLicense(license string) bool {
	if len(license) == 0 {
		return false
	}

	ok, _ := spdxexp.ValidateLicenses([]string{license})
	return ok
}
