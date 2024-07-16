package flag

import (
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/licensing"
)

var (
	LicenseFull = Flag{
		Name:       "license-full",
		ConfigName: "license.full",
		Default:    false,
		Usage:      "eagerly look for licenses in source code headers and license files",
	}
	IgnoredLicenses = Flag{
		Name:       "ignored-licenses",
		ConfigName: "license.ignored",
		Default:    []string{},
		Usage:      "specify a list of license to ignore",
	}
	LicenseConfidenceLevel = Flag{
		Name:       "license-confidence-level",
		ConfigName: "license.confidenceLevel",
		Default:    0.9,
		Usage:      "specify license classifier's confidence level",
	}
	LicenseTextCacheDir = Flag{
		Name:       "license-text-cacheDir",
		ConfigName: "license.cacheDir",
		Default:    "",
		Usage:      "specify the cache dir to persist license texts found in license scanning",
	}
	LicenseScanWorkers = Flag{
		Name:       "license-scan-workers",
		ConfigName: "license.scanWorkers",
		Default:    5,
		Usage:      "specify the number of parallel workers needed for license scanning",
	}

	// LicenseForbidden is an option only in a config file
	LicenseForbidden = Flag{
		ConfigName: "license.forbidden",
		Default:    licensing.ForbiddenLicenses,
		Usage:      "forbidden licenses",
	}
	// LicenseRestricted is an option only in a config file
	LicenseRestricted = Flag{
		ConfigName: "license.restricted",
		Default:    licensing.RestrictedLicenses,
		Usage:      "restricted licenses",
	}
	// LicenseReciprocal is an option only in a config file
	LicenseReciprocal = Flag{
		ConfigName: "license.reciprocal",
		Default:    licensing.ReciprocalLicenses,
		Usage:      "reciprocal licenses",
	}
	// LicenseNotice is an option only in a config file
	LicenseNotice = Flag{
		ConfigName: "license.notice",
		Default:    licensing.NoticeLicenses,
		Usage:      "notice licenses",
	}
	// LicensePermissive is an option only in a config file
	LicensePermissive = Flag{
		ConfigName: "license.permissive",
		Default:    licensing.PermissiveLicenses,
		Usage:      "permissive licenses",
	}
	// LicenseUnencumbered is an option only in a config file
	LicenseUnencumbered = Flag{
		ConfigName: "license.unencumbered",
		Default:    licensing.UnencumberedLicenses,
		Usage:      "unencumbered licenses",
	}
)

type LicenseFlagGroup struct {
	LicenseFull            *Flag
	IgnoredLicenses        *Flag
	LicenseConfidenceLevel *Flag
	LicenseTextCacheDir    *Flag
	LicenseScanWorkers     *Flag

	// License Categories
	LicenseForbidden    *Flag // mapped to CRITICAL
	LicenseRestricted   *Flag // mapped to HIGH
	LicenseReciprocal   *Flag // mapped to MEDIUM
	LicenseNotice       *Flag // mapped to LOW
	LicensePermissive   *Flag // mapped to LOW
	LicenseUnencumbered *Flag // mapped to LOW
}

type LicenseOptions struct {
	LicenseFull            bool
	IgnoredLicenses        []string
	LicenseConfidenceLevel float64
	LicenseRiskThreshold   int
	LicenseCategories      map[types.LicenseCategory][]string
	LicenseTextCacheDir    string
	LicenseScanWorkers     int
}

func NewLicenseFlagGroup() *LicenseFlagGroup {
	return &LicenseFlagGroup{
		LicenseFull:            &LicenseFull,
		IgnoredLicenses:        &IgnoredLicenses,
		LicenseConfidenceLevel: &LicenseConfidenceLevel,
		LicenseTextCacheDir:    &LicenseTextCacheDir,
		LicenseScanWorkers:     &LicenseScanWorkers,
		LicenseForbidden:       &LicenseForbidden,
		LicenseRestricted:      &LicenseRestricted,
		LicenseReciprocal:      &LicenseReciprocal,
		LicenseNotice:          &LicenseNotice,
		LicensePermissive:      &LicensePermissive,
		LicenseUnencumbered:    &LicenseUnencumbered,
	}
}

func (f *LicenseFlagGroup) Name() string {
	return "License"
}

func (f *LicenseFlagGroup) Flags() []*Flag {
	return []*Flag{f.LicenseFull, f.IgnoredLicenses, f.LicenseForbidden, f.LicenseRestricted, f.LicenseReciprocal,
		f.LicenseNotice, f.LicensePermissive, f.LicenseUnencumbered, f.LicenseConfidenceLevel,
		f.LicenseTextCacheDir, f.LicenseScanWorkers}
}

func (f *LicenseFlagGroup) ToOptions() LicenseOptions {
	licenseCategories := make(map[types.LicenseCategory][]string)
	licenseCategories[types.CategoryForbidden] = getStringSlice(f.LicenseForbidden)
	licenseCategories[types.CategoryRestricted] = getStringSlice(f.LicenseRestricted)
	licenseCategories[types.CategoryReciprocal] = getStringSlice(f.LicenseReciprocal)
	licenseCategories[types.CategoryNotice] = getStringSlice(f.LicenseNotice)
	licenseCategories[types.CategoryPermissive] = getStringSlice(f.LicensePermissive)
	licenseCategories[types.CategoryUnencumbered] = getStringSlice(f.LicenseUnencumbered)

	return LicenseOptions{
		LicenseFull:            getBool(f.LicenseFull),
		IgnoredLicenses:        getStringSlice(f.IgnoredLicenses),
		LicenseConfidenceLevel: getFloat(f.LicenseConfidenceLevel),
		LicenseCategories:      licenseCategories,
		LicenseTextCacheDir:    getString(f.LicenseTextCacheDir),
		LicenseScanWorkers:     getInt(f.LicenseScanWorkers),
	}
}
