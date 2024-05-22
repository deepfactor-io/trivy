package nuget

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	godeptypes "github.com/deepfactor-io/go-dep-parser/pkg/types"
	godeputils "github.com/deepfactor-io/go-dep-parser/pkg/utils"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"

	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/utils/fsutils"
)

const nuspecExt = "nuspec"

var _ godeptypes.PackageManifestParser = (*nuspecParser)(nil)

// https://learn.microsoft.com/en-us/nuget/reference/nuspec
type Package struct {
	ID       string
	Metadata Metadata `xml:"metadata"`
}

type Metadata struct {
	Name    string  `xml:"id"`
	Version string  `xml:"version"`
	License License `xml:"license"`
}

type License struct {
	Text string `xml:",chardata"`
	Type string `xml:"type,attr"`
}

type nuspecParser struct {
	packagesDir   string // global packages folder - https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
	licenseConfig types.LicenseScanConfig
}

func newNuspecParser() nuspecParser {
	// cf. https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
	packagesDir := os.Getenv("NUGET_PACKAGES")
	if packagesDir == "" {
		packagesDir = filepath.Join(os.Getenv("HOME"), ".nuget", "packages")
	}

	if !fsutils.DirExists(packagesDir) {
		log.Logger.Debugf("The nuget packages directory couldn't be found. License search disabled")
		return nuspecParser{}
	}

	return nuspecParser{
		packagesDir: packagesDir,
	}
}

func (p nuspecParser) findLicense(name, version string) ([]types.License, error) {
	if p.packagesDir == "" {
		return nil, nil
	}

	// If deep license scanning is enabled, we scan every file present within the given nuget package
	// and search for concluded licenses
	if p.licenseConfig.EnableDeepLicenseScan {
		return p.findLicensesV2(name, version)
	}

	// package path uses lowercase letters only
	// e.g. `$HOME/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`
	// for `Newtonsoft.Json` v13.0.3
	name = strings.ToLower(name)
	version = strings.ToLower(version)

	nuspecFileName := fmt.Sprintf("%s.%s", name, nuspecExt)
	path := filepath.Join(p.packagesDir, name, version, nuspecFileName)

	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %q file: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var pkg Package
	if err = xml.NewDecoder(f).Decode(&pkg); err != nil {
		return nil, xerrors.Errorf("unable to decode %q file: %w", path, err)
	}

	if license := pkg.Metadata.License; license.Type != "expression" || license.Text == "" {
		return nil, nil
	}
	return []types.License{
		{
			Name: pkg.Metadata.License.Text,
		},
	}, nil
}

func (p nuspecParser) findLicensesV2(name, version string) ([]types.License, error) {
	name, version = strings.ToLower(name), strings.ToLower(version)

	// package path uses lowercase letters only
	// e.g. `$HOME/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`
	// for `Newtonsoft.Json` v13.0.3
	rootPath := filepath.Join(p.packagesDir, name, version)
	if !fsutils.DirExists(rootPath) {
		log.Logger.Error(`To collect the license information of package at %q, "dotnet restore" needs to be performed beforehand`, rootPath)
		return nil, nil
	}

	// get the package ID for given package name and version
	pkgID := godeputils.PackageID(name, version)

	walkerInput := fsutils.RecursiveWalkerInput{
		Parser:                    p,
		PackageManifestFile:       fmt.Sprintf("%s.%s", name, nuspecExt),
		PackageDependencyDir:      ".nuget/packages",
		Licenses:                  make(map[string][]types.License),
		ClassifierConfidenceLevel: p.licenseConfig.ClassifierConfidenceLevel,
	}

	// get the file system rooted at given rootPath
	fsys := os.DirFS(rootPath)
	log.Logger.Debugf("Created fsys rooted at root path: %s", rootPath)

	if ret, err := fsutils.RecursiveWalkDir(fsys, ".", "", walkerInput); !ret || err != nil {
		log.Logger.Errorf("recursive walk has failed for dir: %s", rootPath)
	}

	return walkerInput.Licenses[pkgID], nil
}

func (p nuspecParser) ParseManifest(
	fsys fs.FS,
	path string,
) (godeptypes.PackageManifest, error) {
	fp, err := fsys.Open(path)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	var pkg Package
	if err := xml.NewDecoder(fp).Decode(&pkg); err != nil {
		return nil, xerrors.Errorf("unable to decode nuspec manifest file: %w", err)
	}

	name, version := strings.ToLower(pkg.Metadata.Name), strings.ToLower(pkg.Metadata.Version)
	pkg.ID = godeputils.PackageID(name, version)

	return pkg, nil
}

func (p Package) PackageID() string {
	return p.ID
}

func (p Package) DeclaredLicense() string {
	return p.Metadata.License.Text
}
