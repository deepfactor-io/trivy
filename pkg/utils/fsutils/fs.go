package fsutils

import (
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"

	dio "github.com/deepfactor-io/go-dep-parser/pkg/io"
	godeptypes "github.com/deepfactor-io/go-dep-parser/pkg/types"
	"go.uber.org/zap"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	licenseutils "github.com/deepfactor-io/trivy/pkg/fanal/analyzer/licensing"

	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/licensing"
	"github.com/deepfactor-io/trivy/pkg/log"
)

const (
	xdgDataHome = "XDG_DATA_HOME"
)

var cacheDir string

// defaultCacheDir returns/creates the cache-dir to be used for trivy operations
func defaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "deepfactor")
}

// CacheDir returns the directory used for caching
func CacheDir() string {
	if cacheDir == "" {
		return defaultCacheDir()
	}
	return cacheDir
}

// SetCacheDir sets the trivy cacheDir
func SetCacheDir(dir string) {
	cacheDir = dir
}

func HomeDir() string {
	dataHome := os.Getenv(xdgDataHome)
	if dataHome != "" {
		return dataHome
	}

	homeDir, _ := os.UserHomeDir()
	return homeDir
}

// CopyFile copies the file content from scr to dst
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, xerrors.Errorf("file (%s) stat error: %w", src, err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close()
	n, err := io.Copy(destination, source)
	return n, err
}

func DirExists(path string) bool {
	if f, err := os.Stat(path); os.IsNotExist(err) || !f.IsDir() {
		return false
	}
	return true
}

type WalkDirRequiredFunc func(path string, d fs.DirEntry) bool

type WalkDirFunc func(path string, d fs.DirEntry, r io.Reader) error

func WalkDir(fsys fs.FS, root string, required WalkDirRequiredFunc, fn WalkDirFunc) error {
	return fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() || !required(path, d) {
			return nil
		}

		f, err := fsys.Open(path)
		if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}
		defer f.Close()

		if err = fn(path, d, f); err != nil {
			log.Logger.Debugw("Walk error", zap.String("file_path", path), zap.Error(err))
		}
		return nil
	})
}

type RecursiveWalkerInput struct {
	Parser                    godeptypes.PackageManifestParser
	PackageManifestFile       string
	PackageDependencyDir      string
	Licenses                  map[string][]types.License
	ClassifierConfidenceLevel float64
}

// Recursive walker walks the given fs and gets the concluded licenses
// It's Used for deep license scanning.
// Note: For root as ".", we have special handling, please refer below
func RecursiveWalkDir(
	fsys fs.FS,
	root string,
	parentPkgID string,
	input RecursiveWalkerInput,
) (bool, error) {
	var pkgID string
	var foundPackageManifest, foundPackageDependencyDir bool

	log.Logger.Debugf("Input root Path: %s", root)
	// For special packages (like scoped packages in npm), we need to recurse further for scanning
	if isSpecialPath(root) {
		dirEntries, err := fs.ReadDir(fsys, root)
		if err != nil {
			return false, xerrors.Errorf("failed to read dir contents, err: %s\n", err.Error())
		}

		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				dependencyPath := path.Join(root, dirEntry.Name())

				if ret, err := RecursiveWalkDir(fsys, dependencyPath, pkgID, input); !ret || err != nil {
					log.Logger.Errorf("Recursive walker has failed for path: %s", dependencyPath)
				}
			}
		}

		return true, nil
	}

	// Note: For root base path ("."), we scan all the files and add them as loose licenses
	// We don't want to scan pkg manifest file (since they come under loose licenses),
	// nor recursively go to dependency dir (since that's called explicitly from the caller)

	var packageManifestPath string
	if root != "." && input.PackageManifestFile != "" {
		// check if package Manifest file exists, if yes, then parse then we parse it
		packageManifestPath = path.Join(root, input.PackageManifestFile)
		if f, err := fs.Stat(fsys, packageManifestPath); err == nil {
			if f.Size() != 0 {
				pkg, err := input.Parser.ParseManifest(fsys, packageManifestPath)
				if err != nil {
					return false, xerrors.Errorf("unable to parse package manifest, err: %s", err.Error())
				}

				foundPackageManifest = true
				pkgID = pkg.PackageID()

				// If package was already found in the scan, we skip it from license scanning
				if _, ok := input.Licenses[pkgID]; ok {
					log.Logger.Debugf("pkgID is already present, skipping recursive walk. (pkgID: %s, path: %s)", pkgID, root)
					return true, nil
				}

				input.Licenses[pkgID] = []types.License{
					{
						Name:       pkg.DeclaredLicense(),
						IsDeclared: true,
					},
				}
			}
		}
	}

	if !foundPackageManifest {
		log.Logger.Debugf("Package manifest file was not found, checking for parent Pkg ID... (path: %s)", root)

		if parentPkgID == "" {
			log.Logger.Debugf("Parent PkgID is empty. Adding to loose licenses (path: %s)", root)
			pkgID = types.LOOSE_LICENSES
		} else {
			log.Logger.Debugf("Found Parent Pkg ID, using it (path: %s, parent PkgID: %s)", root, parentPkgID)
			pkgID = parentPkgID
		}
	}

	// check if Package dependency dir is present in given root directory
	if root != "." && input.PackageDependencyDir != "" {
		if _, err := fs.Stat(fsys, path.Join(root, input.PackageDependencyDir)); err == nil {
			foundPackageDependencyDir = true
		}
	}

	required := func(filePath string, d fs.DirEntry) bool {
		pkgDependencyDir := path.Join(root, input.PackageDependencyDir)
		// Skip PkgDependency Dir (Ex: node_modules) directory for walk utils
		// Skip checking for Package manifest file and also temporary files
		requiredChecks := (!strings.HasPrefix(filePath, pkgDependencyDir) &&
			!d.IsDir() && !strings.HasPrefix(d.Name(), "~") &&
			filePath != packageManifestPath)

		return requiredChecks
	}

	classifier := func(path string, d fs.DirEntry, r io.Reader) error {
		// apply google license classifier on the given file
		// get the license findings and append to the licenses map
		file, ok := r.(dio.ReadSeekerAt)
		if !ok {
			return xerrors.Errorf("type assertion error, filepath: %s", path)
		}

		concludedLicenses, err := checkForConcludedLicenses(file, path, input.ClassifierConfidenceLevel)
		if err != nil {
			return xerrors.Errorf("failed to get concluded licenses, err: %s", err.Error())
		}

		input.Licenses[pkgID] = append(input.Licenses[pkgID], concludedLicenses...)
		return nil
	}

	// Walk through every file present in given directory except PackageDepepdencyDir
	// Ex: For nested dependency management, like Npm, we skip node_modules dir
	// some files and dirs are skipped via the required func
	if err := WalkDir(fsys, root, required, classifier); err != nil {
		log.Logger.Errorf("walkDir utils failed for root: %s, err: %s\n", root, err.Error())
	}

	// Recursively Walk through the dependencies present in Package dependency directory
	if foundPackageDependencyDir {
		dirEntries, err := fs.ReadDir(fsys, path.Join(root, input.PackageDependencyDir))
		if err != nil {
			return false, xerrors.Errorf("failed to read dir contents, err: %s\n", err.Error())
		}

		for _, dirEntry := range dirEntries {
			if dirEntry.IsDir() {
				dependencyPath := path.Join(root, input.PackageDependencyDir, dirEntry.Name())

				if ret, err := RecursiveWalkDir(fsys, dependencyPath, pkgID, input); !ret || err != nil {
					log.Logger.Errorf("Recursive walker has failed for path: %s", dependencyPath)
				}
			}
		}
	}

	return true, nil
}

func checkForConcludedLicenses(
	r dio.ReadSeekerAt,
	filePath string,
	classifierConfidenceLevel float64,
) ([]types.License, error) {
	var concludedLicenses []types.License
	if readable, err := licenseutils.IsHumanReadable(r, math.MaxInt); err != nil || !readable {
		return concludedLicenses, nil
	}

	lf, err := licensing.Classify(filePath, r, classifierConfidenceLevel)
	if err != nil {
		return concludedLicenses, err
	}

	for _, finding := range lf.Findings {
		license := types.License{
			Name:          finding.Name,
			Type:          lf.Type,
			IsDeclared:    false,
			LicenseText:   finding.LicenseText,
			CopyrightText: finding.CopyRightText,
			FilePath:      lf.FilePath,
			Findings:      lf.Findings, // for loose licenses we need these license findings
		}

		concludedLicenses = append(concludedLicenses, license)
	}

	return concludedLicenses, nil
}

func isSpecialPath(path string) bool {
	// In case of NPM, scoped packages come under this.
	return strings.HasPrefix(filepath.Base(path), "@")
}

func RequiredExt(exts ...string) WalkDirRequiredFunc {
	return func(filePath string, _ fs.DirEntry) bool {
		return slices.Contains(exts, filepath.Ext(filePath))
	}
}

func RequiredFile(fileNames ...string) WalkDirRequiredFunc {
	return func(filePath string, _ fs.DirEntry) bool {
		return slices.Contains(fileNames, filepath.Base(filePath))
	}
}
