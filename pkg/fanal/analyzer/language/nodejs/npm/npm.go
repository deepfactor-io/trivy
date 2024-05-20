package npm

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/deepfactor-io/go-dep-parser/pkg/io"
	"github.com/deepfactor-io/go-dep-parser/pkg/nodejs/npm"
	"github.com/deepfactor-io/go-dep-parser/pkg/nodejs/packagejson"
	godeptypes "github.com/deepfactor-io/go-dep-parser/pkg/types"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/language"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/utils/fsutils"
	xpath "github.com/deepfactor-io/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNpmPkgLock, newNpmLibraryAnalyzer)
}

const (
	version = 1
)

type npmLibraryAnalyzer struct {
	lockParser    godeptypes.Parser
	packageParser *packagejson.Parser
	licenseConfig types.LicenseScanConfig
}

var _ godeptypes.PackageManifestParser = (*npmLibraryAnalyzer)(nil)

func newNpmLibraryAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	analyzer := &npmLibraryAnalyzer{
		lockParser:    npm.NewParser(),
		packageParser: packagejson.NewParser(),
	}

	if opt.LicenseScannerOption.Enabled && opt.LicenseScannerOption.Full {
		analyzer.licenseConfig = types.LicenseScanConfig{
			EnableDeepLicenseScan:     true,
			ClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
		}

		log.Logger.Debug("Deep license scanning enabled for Npm Library Analyzer")
	}

	return analyzer, nil
}

func (a npmLibraryAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	// Parse package-lock.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkgLock
	}

	var apps []types.Application
	err := fsutils.WalkDir(input.FS, ".", required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		// Find all licenses from package.json files under node_modules dirs
		// If deep license scanning is enabled, it also gets the concluded licenses.
		licenses, err := a.findLicenses(input.FS, filePath)
		if err != nil {
			log.Logger.Errorf("Unable to collect licenses: %s", err.Error())
		}

		app, err := a.parseNpmPkgLock(input.FS, filePath)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Fill licenses
		for i, lib := range app.Libraries {
			if licenses, ok := licenses[lib.ID]; ok {
				for _, license := range licenses {
					app.Libraries[i].Licenses = append(app.Libraries[i].Licenses, license.Name)
				}

				app.Libraries[i].LicensesV2 = append(app.Libraries[i].LicensesV2, licenses...)
			}
		}

		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("package-lock.json/package.json walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a npmLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Note: this is the main step where the file system is filtered and passed to above PostAnalyze API
	// Only files which pass this Required check would be added to the filtered file system
	if a.licenseConfig.EnableDeepLicenseScan {
		// TODO add some required checks to filter out files needed for deep license scanning

		// node_modules dir is scanned as part of findLicenses, so we skip it here
		// why only NpmPkgLock? this is the required file as part of PostAnalyze
		fileName := filepath.Base(filePath)
		if fileName == types.NpmPkgLock && xpath.Contains(filePath, "node_modules") {
			return false
		}

		return true
	}

	fileName := filepath.Base(filePath)
	if fileName == types.NpmPkgLock && !xpath.Contains(filePath, "node_modules") {
		return true
	}
	// The file path to package.json - */node_modules/<package_name>/package.json
	// The path is slashed in analyzers.
	dirs := strings.Split(path.Dir(filePath), "/")
	if len(dirs) > 1 && dirs[len(dirs)-2] == "node_modules" && fileName == types.NpmPkg {
		return true
	}

	return false
}

func (a npmLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNpmPkgLock
}

func (a npmLibraryAnalyzer) Version() int {
	return version
}

func (a npmLibraryAnalyzer) parseNpmPkgLock(fsys fs.FS, filePath string) (*types.Application, error) {
	f, err := fsys.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(dio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// parse package-lock.json file
	return language.Parse(types.Npm, filePath, file, a.lockParser)
}

func (a npmLibraryAnalyzer) findLicenses(fsys fs.FS, lockPath string) (map[string][]types.License, error) {
	// If deep license scanning is enabled, we scan every file present in the repo and node_modules
	// and search for concluded licenses
	if a.licenseConfig.EnableDeepLicenseScan {
		return a.findLicensesV2(fsys, lockPath)
	}

	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		log.Logger.Infof(`To collect the license information of packages in %q, "npm install" needs to be performed beforehand`, lockPath)
		return nil, nil
	}

	// Parse package.json
	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.NpmPkg
	}

	// Traverse node_modules dir and find licenses
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than filepath.Join.
	licenses := make(map[string][]types.License)
	err := fsutils.WalkDir(fsys, root, required, func(filePath string, d fs.DirEntry, r io.Reader) error {
		pkg, err := a.packageParser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", filePath, err)
		}

		licenses[pkg.PackageID()] = append(licenses[pkg.PackageID()], types.License{Name: pkg.DeclaredLicense()})
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}
	return licenses, nil
}

func (a npmLibraryAnalyzer) findLicensesV2(fsys fs.FS, lockPath string) (map[string][]types.License, error) {
	dir := path.Dir(lockPath)
	root := path.Join(dir, "node_modules")
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		log.Logger.Infof(`To collect the license information of packages in %q, "npm install" needs to be performed beforehand`, lockPath)
		return nil, nil
	}

	// Traverse node_modules dir and find licenses
	// Note that fs.FS is always slashed regardless of the platform,
	// and path.Join should be used rather than path.Join.

	walkerInput := fsutils.RecursiveWalkerInput{
		Parser:                    a,
		PackageManifestFile:       types.NpmPkg,
		PackageDependencyDir:      types.NpmDependencyDir,
		Licenses:                  make(map[string][]types.License),
		ClassifierConfidenceLevel: a.licenseConfig.ClassifierConfidenceLevel,
	}

	if ret, err := fsutils.RecursiveWalkDir(fsys, dir, "", walkerInput); !ret || err != nil {
		log.Logger.Errorf("recursive walk has failed for dir: %s", dir)
	}

	dirEntries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, xerrors.Errorf("failed to read dir contents, err: %s", err.Error())
	}

	// Apply Recursive Walker on each dependency present in node_modules
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			dependencyPath := path.Join(root, dirEntry.Name())

			if ret, err := fsutils.RecursiveWalkDir(fsys, dependencyPath, "", walkerInput); !ret || err != nil {
				log.Logger.Errorf("recursive walk has failed for dir: %s", dependencyPath)
			}
		}
	}

	/*
		// Apply Recursive Walker on the repo root directory
		if ret, err := a.recursiveWalkDir(fsys, dir, "", licenses); !ret || err != nil {
			log.Logger.Errorf("recursive walk has failed for dir: %s", dir)
		}

		dirEntries, err := fs.ReadDir(fsys, root)
		if err != nil {
			return nil, xerrors.Errorf("failed to read dir contents, err: %s", err.Error())
		}

		// Apply Recursive Walker on each dependency present in node_modules
		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				dependencyPath := path.Join(root, dirEntry.Name())
				if ret, err := a.recursiveWalkDir(fsys, dependencyPath, "", licenses); !ret || err != nil {
					log.Logger.Errorf("recursive walk has failed for dir: %s", dependencyPath)
				}
			}
		}
	*/

	return walkerInput.Licenses, nil
}

// parses the package manifest file present at the given root path
func (a npmLibraryAnalyzer) ParseManifest(
	fsys fs.FS,
	path string,
) (godeptypes.PackageManifest, error) {
	fp, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	pkg, err := a.packageParser.Parse(fp)
	if err != nil {
		return pkg, xerrors.Errorf("err while parsing package manifest: %s", err.Error())
	}

	return pkg, nil
}

/*
func (a npmLibraryAnalyzer) recursiveWalkDir(
	fsys fs.FS,
	root string,
	parentPkgID string,
	licenses map[string][]types.License,
) (bool, error) {
	var pkgID string
	var foundPackageManifest, foundPackageDependencyDir bool

	// check if package.json exists, if yes, then parse the package.json
	if f, err := fs.Stat(fsys, path.Join(root, types.NpmPkg)); err == nil {
		if f.Size() != 0 {
			f, err := fsys.Open(path.Join(root, types.NpmPkg))
			if err != nil {
				return false, xerrors.Errorf("failed to open manifest file, err: %s", err.Error())
			}

			pkg, err := a.ParseManifest(f)
			f.Close()
			if err != nil {
				return false, xerrors.Errorf("unable to parse package manifest, err: %s", err.Error())
			}

			foundPackageManifest = true
			pkgID = pkg.PackageID()

			// If package was already found in the scan, we skip it from license scanning
			if _, ok := licenses[pkgID]; ok {
				log.Logger.Debugf("pkgID is already present, skipping recursive walk. (pkgID: %s, path: %s)", pkgID, root)
				return true, nil
			}

			licenses[pkgID] = []types.License{
				{
					Name:       pkg.DeclaredLicense(),
					IsDeclared: true,
				},
			}
		}
	}

	if !foundPackageManifest {
		if parentPkgID == "" {
			log.Logger.Debugf("Package manifest was not found & parent pkgID is empty, returning. (path: %s)", root)
			return true, nil
		}

		log.Logger.Debugf("Package manifest was not found, using parent pkgID: %s", parentPkgID)
		pkgID = parentPkgID
	}

	// check if node_modules is present in given root directory
	if _, err := fs.Stat(fsys, path.Join(root, types.NpmDependencyDir)); err == nil {
		foundPackageDependencyDir = true
	}

	required := func(filepath string, d fs.DirEntry) bool {
		pkgDependencyDir := path.Join(root, types.NpmDependencyDir)

		// Skip node_modules directory for walk utils
		requiredDirs := (!strings.HasPrefix(filepath, ".") && !strings.HasPrefix(filepath, pkgDependencyDir))

		// skip checking for package.json and also temporary files
		requiredFiles := (!d.IsDir() && !strings.HasPrefix(d.Name(), "~") && d.Name() != types.NpmPkg)

		return requiredDirs && requiredFiles
	}

	classifier := func(path string, d fs.DirEntry, r io.Reader) error {
		// apply google license classifier on the given file
		// get the license findings and append to the licenses map
		file, ok := r.(dio.ReadSeekerAt)
		if !ok {
			return xerrors.Errorf("type assertion error: failed to convert to dio.ReadSeekerAt (filepath: %s)", path)
		}

		concludedLicenses, err := a.checkForConcludedLicenses(file, path)
		if err != nil {
			return xerrors.Errorf("failed to get concluded licenses, err: %s", err.Error())
		}

		licenses[pkgID] = append(licenses[pkgID], concludedLicenses...)
		return nil
	}

	// Walk through every file present in given directory except node_modules.
	// some files and dirs are skipped via the required func
	if err := fsutils.WalkDir(fsys, root, required, classifier); err != nil {
		log.Logger.Errorf("walkDir utils failed, err: %s", err.Error())
	}

	// Recursively Walk through the dependencies present in node_modules directory
	if foundPackageDependencyDir {
		dirEntries, err := fs.ReadDir(fsys, path.Join(root, types.NpmDependencyDir))
		if err != nil {
			return false, xerrors.Errorf("failed to read dir contents, err: %s", err.Error())
		}

		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				dependencyPath := path.Join(root, types.NpmDependencyDir, dirEntry.Name())
				if ret, err := a.recursiveWalkDir(fsys, dependencyPath, pkgID, licenses); !ret || err != nil {
					return false, err
				}
			}
		}
	}

	return true, nil
}

func (a npmLibraryAnalyzer) checkForConcludedLicenses(
	r dio.ReadSeekerAt,
	filePath string,
) ([]types.License, error) {
	var concludedLicenses []types.License
	if readable, err := licenseutils.IsHumanReadable(r, math.MaxInt); err != nil || !readable {
		return concludedLicenses, nil
	}

	lf, err := licensing.Classify(filePath, r, a.licenseConfig.ClassifierConfidenceLevel)
	if err != nil {
		return concludedLicenses, err
	}

	for _, finding := range lf.Findings {
		license := types.License{
			Name:        finding.Name,
			Type:        lf.Type,
			IsDeclared:  false,
			LicenseText: finding.Link, // TODO TBD
			FilePath:    lf.FilePath,
		}

		concludedLicenses = append(concludedLicenses, license)
	}

	return concludedLicenses, nil
}
*/
