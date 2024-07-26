package local

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/wire"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ospkgDetector "github.com/deepfactor-io/trivy/pkg/detector/ospkg"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/applier"
	"github.com/deepfactor-io/trivy/pkg/fanal/artifact"
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/utils"

	"github.com/deepfactor-io/trivy/pkg/iac/rego"
	"github.com/deepfactor-io/trivy/pkg/licensing"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/scanner/langpkg"
	"github.com/deepfactor-io/trivy/pkg/scanner/ospkg"
	"github.com/deepfactor-io/trivy/pkg/scanner/post"
	"github.com/deepfactor-io/trivy/pkg/types"
	"github.com/deepfactor-io/trivy/pkg/vulnerability"

	_ "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/all"
	_ "github.com/deepfactor-io/trivy/pkg/fanal/handler/all"
)

// SuperSet binds dependencies for Local scan
var SuperSet = wire.NewSet(
	vulnerability.SuperSet,
	applier.NewApplier,
	ospkg.NewScanner,
	langpkg.NewScanner,
	NewScanner,
)

// Scanner implements the OspkgDetector and LibraryDetector
type Scanner struct {
	applier        applier.Applier
	osPkgScanner   ospkg.Scanner
	langPkgScanner langpkg.Scanner
	vulnClient     vulnerability.Client
}

// NewScanner is the factory method for Scanner
func NewScanner(a applier.Applier, osPkgScanner ospkg.Scanner, langPkgScanner langpkg.Scanner,
	vulnClient vulnerability.Client) Scanner {
	return Scanner{
		applier:        a,
		osPkgScanner:   osPkgScanner,
		langPkgScanner: langPkgScanner,
		vulnClient:     vulnClient,
	}
}

// Scan scans the artifact and return results.
func (s Scanner) Scan(ctx context.Context, targetName, artifactKey string, blobKeys []string, options types.ScanOptions) (
	types.Results, ftypes.OS, error) {
	detail, err := s.applier.ApplyLayers(artifactKey, blobKeys)
	switch {
	case errors.Is(err, analyzer.ErrUnknownOS):
		log.Debug("OS is not detected.")

		// Packages may contain OS-independent binary information even though OS is not detected.
		if len(detail.Packages) != 0 {
			detail.OS = ftypes.OS{Family: "none"}
		}

		// If OS is not detected and repositories are detected, we'll try to use repositories as OS.
		if detail.Repository != nil {
			log.Debug("Package repository", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			log.Debug("Assuming OS", log.String("family", string(detail.Repository.Family)),
				log.String("version", detail.Repository.Release))
			detail.OS = ftypes.OS{
				Family: detail.Repository.Family,
				Name:   detail.Repository.Release,
			}
		}
	case errors.Is(err, analyzer.ErrNoPkgsDetected):
		log.Warn("No OS package is detected. Make sure you haven't deleted any files that contain information about the installed packages.")
		log.Warn(`e.g. files under "/lib/apk/db/", "/var/lib/dpkg/" and "/var/lib/rpm"`)
	case err != nil:
		return nil, ftypes.OS{}, xerrors.Errorf("failed to apply layers: %w", err)
	}

	target := types.ScanTarget{
		Name:              targetName,
		OS:                detail.OS,
		Repository:        detail.Repository,
		Packages:          mergePkgs(detail.Packages, detail.ImageConfig.Packages, options),
		Applications:      postProcessApplications(detail.Applications, options),
		Misconfigurations: mergeMisconfigurations(targetName, detail),
		Secrets:           mergeSecrets(targetName, detail),
		Licenses:          detail.Licenses,
		CustomResources:   detail.CustomResources,
	}

	return s.ScanTarget(ctx, target, options)
}

// post process applications to
// 1. Add root dependency info
// 2. Split package which is both direct and indirect to two entries
// 3. Dedupe node packages (image scan): get transitive info from lock files and copy it to node installed packages
// 4. Dedupe composer packages (image scan): get isDev info from composer.json and copy it to composer installed packages
func postProcessApplications(apps []ftypes.Application, options types.ScanOptions) []ftypes.Application {
	// Map to store nodejs lock file packages
	nodeLockFilePackages := map[string]ftypes.Package{}
	reqPHPPackages := make(map[string]struct{})
	reqDevPHPPackages := make(map[string]struct{})

	for i, app := range apps {
		if len(app.Packages) == 0 {
			continue
		}

		isPkgSplitRequired := utils.IsPkgSplitRequired(app.Type)

		// Get parents map for current target
		parents := ftypes.Packages(app.Packages).ParentDeps()

		// get node application directory info from the filepath
		// required for deduplication
		nodeAppDirInfo := utils.NodeAppDirInfo(app.FilePath)

		for i, pkg := range app.Packages {

			// calculate rootDep
			if len(parents) != 0 && (pkg.Indirect || isPkgSplitRequired) {
				pkg.RootDependencies = utils.FindAncestor(pkg.ID, parents, map[string]struct{}{})
				app.Packages[i] = pkg

				// if a pkg which is direct and has atleast one root dependency we will consisder it as both direct and indirect
				// so we split the entry into two and move root deps to the new entry (i.e the indirect entry).
				// note: for image scans, node installed package won't have transitive info at this point of time, so we handle that in dedupe process.
				// since vulnerability detect function operates on app.Libraries, we will get two vulnerability (of same ID)
				// one for pkgA-direct and one for pkgA-indirect, this is required because we need to highlight them separately in the final report
				if isPkgSplitRequired && !pkg.Indirect && len(pkg.RootDependencies) > 0 {
					indirectPkg := pkg
					indirectPkg.Indirect = true
					app.Packages = append(app.Packages, indirectPkg)

					// remove rootdeps from direct dep
					app.Packages[i].RootDependencies = []string{}
				}
			}

			// store node lockfile (npm, yarn, pnpm) package info (ignore lock files which are present in locations other than App Directory eg: node_modules/pkg/{lockfile})
			// will be utilzed for node dedupe (tansitive & rootDep info)
			if nodeAppDirInfo.IsNodeLockFile && nodeAppDirInfo.IsFileinAppDir {
				nodeLockFilePackages[nodeAppDirInfo.GetPackageKey(pkg)] = pkg
			}

			// store PHP dev package info
			// will be utilized for PHP deduping (isDev info)
			if app.Type == ftypes.ComposerJSON {
				if pkg.Dev {
					reqDevPHPPackages[pkg.Name] = struct{}{}
				} else {
					reqPHPPackages[pkg.Name] = struct{}{}
				}
			}
		}

		// update apps
		apps[i] = app
	}

	// dedupe data for image scans
	// combining data from lock files to the installed packages for node and composer
	if options.ArtifactType == artifact.TypeContainerImage {
		apps = utils.DedupePackages(utils.DedupeFilter{
			NodeLockFilePackages: nodeLockFilePackages,
			ReqDevPHPPackages:    reqDevPHPPackages,
			ReqPHPPackages:       reqPHPPackages,
		}, apps)
	}

	return apps
}

func (s Scanner) ScanTarget(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (types.Results, ftypes.OS, error) {
	var results types.Results

	// By default, we need to remove dev dependencies from the result
	// IncludeDevDeps option allows you not to remove them
	excludeDevDeps(target.Applications, options.IncludeDevDeps)

	// Add packages if needed and scan packages for vulnerabilities
	vulnResults, eosl, err := s.scanVulnerabilities(ctx, target, options)
	if err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("failed to detect vulnerabilities: %w", err)
	}
	target.OS.Eosl = eosl
	results = append(results, vulnResults...)

	// Store misconfigurations
	results = append(results, s.misconfsToResults(target.Misconfigurations, options)...)

	// Store secrets
	results = append(results, s.secretsToResults(target.Secrets, options)...)

	// Scan licenses
	results = append(results, s.scanLicenses(target, options)...)

	// For WASM plugins and custom analyzers
	if len(target.CustomResources) != 0 {
		results = append(results, types.Result{
			Class:           types.ClassCustom,
			CustomResources: target.CustomResources,
		})
	}

	for i := range results {
		// Fill vulnerability details
		s.vulnClient.FillInfo(results[i].Vulnerabilities)
	}

	// Post scanning
	results, err = post.Scan(ctx, results)
	if err != nil {
		return nil, ftypes.OS{}, xerrors.Errorf("post scan error: %w", err)
	}

	return results, target.OS, nil
}

func (s Scanner) scanVulnerabilities(ctx context.Context, target types.ScanTarget, options types.ScanOptions) (
	types.Results, bool, error) {
	if !options.Scanners.AnyEnabled(types.SBOMScanner, types.VulnerabilityScanner) {
		return nil, false, nil
	}

	var eosl bool
	var results types.Results

	if slices.Contains(options.VulnType, types.VulnTypeOS) {
		vuln, detectedEOSL, err := s.osPkgScanner.Scan(ctx, target, options)
		switch {
		case errors.Is(err, ospkgDetector.ErrUnsupportedOS):
		// do nothing
		case err != nil:
			return nil, false, xerrors.Errorf("unable to scan OS packages: %w", err)
		case vuln.Target != "":
			results = append(results, vuln)
			eosl = detectedEOSL
		}
	}

	if slices.Contains(options.VulnType, types.VulnTypeLibrary) {
		vulns, err := s.langPkgScanner.Scan(ctx, target, options)
		if err != nil {
			return nil, false, xerrors.Errorf("failed to scan application libraries: %w", err)
		}
		results = append(results, vulns...)
	}

	return results, eosl, nil
}

func (s Scanner) misconfsToResults(misconfs []ftypes.Misconfiguration, options types.ScanOptions) types.Results {
	if !ShouldScanMisconfigOrRbac(options.Scanners) &&
		!options.ImageConfigScanners.Enabled(types.MisconfigScanner) {
		return nil
	}

	return s.MisconfsToResults(misconfs)
}

// MisconfsToResults is exported for trivy-plugin-aqua purposes only
func (s Scanner) MisconfsToResults(misconfs []ftypes.Misconfiguration) types.Results {
	log.Info("Detected config files", log.Int("num", len(misconfs)))
	var results types.Results
	for _, misconf := range misconfs {
		log.Debug("Scanned config file", log.FilePath(misconf.FilePath))

		var detected []types.DetectedMisconfiguration

		for _, f := range misconf.Failures {
			detected = append(detected, toDetectedMisconfiguration(f, dbTypes.SeverityCritical, types.MisconfStatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Warnings {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityMedium, types.MisconfStatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Successes {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.MisconfStatusPassed, misconf.Layer))
		}
		for _, w := range misconf.Exceptions {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, types.MisconfStatusException, misconf.Layer))
		}

		results = append(results, types.Result{
			Target:            misconf.FilePath,
			Class:             types.ClassConfig,
			Type:              misconf.FileType,
			Misconfigurations: detected,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})

	return results
}

func (s Scanner) secretsToResults(secrets []ftypes.Secret, options types.ScanOptions) types.Results {
	if !options.Scanners.Enabled(types.SecretScanner) {
		return nil
	}

	var results types.Results
	for _, secret := range secrets {
		log.Debug("Secret file", log.FilePath(secret.FilePath))

		results = append(results, types.Result{
			Target: secret.FilePath,
			Class:  types.ClassSecret,
			Secrets: lo.Map(secret.Findings, func(secret ftypes.SecretFinding, index int) types.DetectedSecret {
				return types.DetectedSecret(secret)
			}),
		})
	}
	return results
}

// Func gets the licenses for os-pkgs, lang-pkgs, license-file and wrap around types.Result
// If full license scanning is disabled -- it adds os-pkgs & lang-pkgs (declared) licenses
// If full license scanning is enabled -- it adds os-pkgs & lang-pkgs (declared + concluded) + loose file licenses
func (s Scanner) scanLicenses(target types.ScanTarget, options types.ScanOptions) types.Results {
	var results types.Results
	scanner := licensing.NewScanner(options.LicenseCategories)

	// License - OS packages
	var osPkgLicenses []types.DetectedLicense
	var osPkgTarget = fmt.Sprintf("%s (%s %s)", target.Name, target.OS.Family, target.OS.Name)
	for i := range target.Packages {
		pkg := &target.Packages[i]
		pkg.Licenses = utils.FilterNGetLicenses(pkg.Licenses)

		for _, license := range pkg.Licenses {
			category, severity := scanner.Scan(license)
			osPkgLicenses = append(osPkgLicenses, types.DetectedLicense{
				Severity:         severity,
				Category:         category,
				Name:             license,
				IsDeclared:       true,
				IsSPDXClassified: utils.ValidateLicense(license),
				PkgName:          pkg.Name,
				PkgFilePath:      pkg.FilePath,
				PkgType:          target.OS.Family,
				PkgVersion:       pkg.Version,
				PkgClass:         types.ClassOSPkg,
				PkgTarget:        osPkgTarget,
				IsPkgIndirect:    pkg.Indirect,
				PkgEpoch:         pkg.Epoch,
				PkgRelease:       pkg.Release,
				PkgID:            pkg.ID,
			})
		}
	}
	results = append(results, types.Result{
		Target:   types.LicenseTargetOSPkg,
		Class:    types.ClassLicense,
		Licenses: osPkgLicenses,
	})

	// License - language-specific packages
	for _, app := range target.Applications {
		targetName := app.FilePath
		if t, ok := langpkg.PkgTargets[app.Type]; ok && targetName == "" {
			// When the file path is empty, we will overwrite it with the pre-defined value.
			targetName = t
		}

		var langLicenses []types.DetectedLicense
		for i := range app.Packages {
			lib := &app.Packages[i]
			lib.Licenses = utils.FilterNGetLicenses(lib.Licenses)

			// Declared licenses are stored in the Licenses array
			for _, license := range lib.Licenses {
				category, severity := scanner.Scan(license)
				langLicenses = append(langLicenses, types.DetectedLicense{
					Severity: severity,
					Category: category,
					Name:     license,
					// Lock files use app.FilePath - https://github.com/deepfactor-io/trivy/blob/6ccc0a554b07b05fd049f882a1825a0e1e0aabe1/pkg/fanal/types/artifact.go#L245-L246
					// Applications use lib.FilePath - https://github.com/deepfactor-io/trivy/blob/6ccc0a554b07b05fd049f882a1825a0e1e0aabe1/pkg/fanal/types/artifact.go#L93-L94
					FilePath:         lo.Ternary(lib.FilePath != "", lib.FilePath, app.FilePath),
					Confidence:       1.0,
					IsDeclared:       true,
					IsSPDXClassified: utils.ValidateLicense(license),
					PkgName:          lib.Name,
					PkgFilePath:      lib.FilePath,
					PkgVersion:       lib.Version,
					PkgClass:         types.ClassLangPkg,
					PkgType:          app.Type,
					PkgTarget:        targetName,
					IsPkgIndirect:    lib.Indirect,
					PkgEpoch:         lib.Epoch,
					PkgRelease:       lib.Release,
					PkgID:            lib.ID,
				})
			}

			// Concluded licenses are stored in ConcludedLicenses array
			for _, license := range lib.ConcludedLicenses {
				category, severity := scanner.Scan(license.Name)
				langLicenses = append(langLicenses, types.DetectedLicense{
					Severity:            severity,
					Category:            category,
					Name:                license.Name,
					IsDeclared:          license.IsDeclared,
					IsSPDXClassified:    utils.ValidateLicense(license.Name),
					FilePath:            license.FilePath,
					LicenseTextChecksum: license.LicenseTextChecksum,
					CopyrightText:       license.CopyrightText,
					PkgName:             lib.Name,
					PkgFilePath:         lib.FilePath,
					PkgVersion:          lib.Version,
					PkgClass:            types.ClassLangPkg,
					PkgType:             app.Type,
					PkgTarget:           targetName,
					IsPkgIndirect:       lib.Indirect,
					PkgEpoch:            lib.Epoch,
					PkgRelease:          lib.Release,
					PkgID:               lib.ID,
				})
			}
		}

		results = append(results, types.Result{
			Target:   targetName,
			Class:    types.ClassLicense,
			Licenses: langLicenses,
		})
	}

	if !options.Scanners.Enabled(types.LicenseScanner) || !options.LicenseFull {
		return results
	}

	// License - file header or license file
	var fileLicenses []types.DetectedLicense
	for _, license := range target.Licenses {
		for _, finding := range license.Findings {
			category, severity := scanner.Scan(finding.Name)
			fileLicenses = append(fileLicenses, types.DetectedLicense{
				Severity:            severity,
				Category:            category,
				FilePath:            license.FilePath,
				Name:                finding.Name,
				IsSPDXClassified:    utils.ValidateLicense(finding.Name),
				Confidence:          finding.Confidence,
				Link:                finding.Link,
				LicenseTextChecksum: finding.LicenseTextChecksum,
				CopyrightText:       finding.CopyRightText,
			})

		}
	}
	results = append(results, types.Result{
		Target:   types.LicenseTargetLicenseFile,
		Class:    types.ClassLicenseFile,
		Licenses: fileLicenses,
	})

	return results
}

func toDetectedMisconfiguration(res ftypes.MisconfResult, defaultSeverity dbTypes.Severity,
	status types.MisconfStatus, layer ftypes.Layer) types.DetectedMisconfiguration {

	severity := defaultSeverity
	sev, err := dbTypes.NewSeverity(res.Severity)
	if err != nil {
		log.Warn("Unsupported severity", log.String("severity", res.Severity))
	} else {
		severity = sev
	}

	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = "No issues found"
	}

	var primaryURL string

	// empty namespace implies a go rule from defsec, "builtin" refers to a built-in rego rule
	// this ensures we don't generate bad links for custom policies
	if res.Namespace == "" || rego.IsBuiltinNamespace(res.Namespace) {
		primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(res.ID))
		res.References = append(res.References, primaryURL)
	}

	if primaryURL == "" && len(res.References) > 0 {
		primaryURL = res.References[0]
	}

	return types.DetectedMisconfiguration{
		ID:          res.ID,
		AVDID:       res.AVDID,
		Type:        res.Type,
		Title:       res.Title,
		Description: res.Description,
		Message:     msg,
		Resolution:  res.RecommendedActions,
		Namespace:   res.Namespace,
		Query:       res.Query,
		Severity:    severity.String(),
		PrimaryURL:  primaryURL,
		References:  res.References,
		Status:      status,
		Layer:       layer,
		Traces:      res.Traces,
		CauseMetadata: ftypes.CauseMetadata{
			Resource:    res.Resource,
			Provider:    res.Provider,
			Service:     res.Service,
			StartLine:   res.StartLine,
			EndLine:     res.EndLine,
			Code:        res.Code,
			Occurrences: res.Occurrences,
		},
	}
}

func ShouldScanMisconfigOrRbac(scanners types.Scanners) bool {
	return scanners.AnyEnabled(types.MisconfigScanner, types.RBACScanner)
}

func mergePkgs(pkgs, pkgsFromCommands []ftypes.Package, options types.ScanOptions) []ftypes.Package {
	if !options.ScanRemovedPackages || len(pkgsFromCommands) == 0 {
		return pkgs
	}

	// pkg has priority over pkgsFromCommands
	uniqPkgs := make(map[string]struct{})
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}

// mergeMisconfigurations merges misconfigurations on container image config
func mergeMisconfigurations(targetName string, detail ftypes.ArtifactDetail) []ftypes.Misconfiguration {
	if detail.ImageConfig.Misconfiguration == nil {
		return detail.Misconfigurations
	}

	// Append misconfigurations on container image config
	misconf := detail.ImageConfig.Misconfiguration
	misconf.FilePath = targetName // Set the target name to the file path as container image config is not a real file.
	return append(detail.Misconfigurations, *misconf)
}

// mergeSecrets merges secrets on container image config.
func mergeSecrets(targetName string, detail ftypes.ArtifactDetail) []ftypes.Secret {
	if detail.ImageConfig.Secret == nil {
		return detail.Secrets
	}

	// Append secrets on container image config
	secret := detail.ImageConfig.Secret
	secret.FilePath = targetName // Set the target name to the file path as container image config is not a real file.
	return append(detail.Secrets, *secret)
}

// excludeDevDeps removes development dependencies from the list of applications
func excludeDevDeps(apps []ftypes.Application, include bool) {
	if include {
		return
	}
	for i := range apps {
		// Not filtering ftypes.ComposerInstalled, ftypes.ComposerJSON cos the isDev info is necessary for finding
		// direct/indirect attributes accurately. We anyway don't highlight these deps as dev/non dev in UI
		// since static scanner controls thats behaviour
		apps[i].Packages = lo.Filter(apps[i].Packages, func(lib ftypes.Package, index int) bool {
			return !lib.Dev || (lib.Dev && lo.IndexOf([]ftypes.TargetType{ftypes.ComposerInstalled, ftypes.ComposerJSON}, apps[i].Type) != -1)
		})
	}
}
