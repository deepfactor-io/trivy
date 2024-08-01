package library

import (
	"golang.org/x/xerrors"

	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/v3/pkg/types"
)

// Detect scans and returns vulnerabilities of library
func Detect(libType ftypes.LangType, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	driver, ok := NewDriver(libType)
	if !ok {
		return nil, nil
	}

	vulns, err := detect(driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(driver Driver, libs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		vulns, err := driver.DetectVulnerabilities(lib.ID, lib.Name, lib.Version)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = lib.Layer
			vulns[i].PkgPath = lib.FilePath
			vulns[i].PkgRef = lib.Ref
			vulns[i].PkgDev = lib.Dev
			vulns[i].PkgIndirect = lib.Indirect
			vulns[i].PkgRootDependencies = lib.RootDependencies
			vulns[i].NodeDedupeMatchFound = lib.NodeDedupeMatchFound
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}
