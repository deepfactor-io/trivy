package types

import "github.com/deepfactor-io/trivy/pkg/fanal/types"

type DetectedLicense struct {
	// Severity is the consistent parameter indicating how severe the issue is
	Severity string

	// Category holds the license category such as "forbidden"
	Category types.LicenseCategory

	// PkgName holds a package name which used the license.
	// It will be empty if FilePath is filled.
	PkgName string

	// PkgVersion holds the package version which used the license
	// It will be empty if FilePath is filled
	PkgVersion string

	// PkgName holds a file path of the license.
	// It will be empty if PkgName is filled.
	FilePath string // for file license

	// Name holds a detected license name
	Name string

	// Type of the detected license
	Type types.LicenseType

	// true if license is a declared license, else it's a concluded license
	IsDeclared bool

	// Entire license text found in LICENSE file or within source code
	LicenseText string // for license files

	// Copyright text found as a file or within the source code
	CopyrightText string

	// Confidence is level of the match. The confidence level is between 0.0 and 1.0, with 1.0 indicating an
	// exact match and 0.0 indicating a complete mismatch
	Confidence float64

	// Link is a SPDX link of the license
	Link string
}
