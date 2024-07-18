package composer

import (
	"io"
	"sort"
	"strings"

	"github.com/liamg/jfather"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/pkg/dependency"
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/licensing"
	"github.com/deepfactor-io/trivy/pkg/log"
	xio "github.com/deepfactor-io/trivy/pkg/x/io"
)

type LockFile struct {
	Packages        []packageInfo `json:"packages"`
	DevPackages     []packageInfo `json:"packages-dev"`
	DevPackageNames []string      `json:"dev-package-names"` // this is to handle dev packages in case of installed.json
}
type packageInfo struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Require   map[string]string `json:"require"`
	License   []string          `json:"license"`
	StartLine int
	EndLine   int
}

type Parser struct {
	logger          *log.Logger
	devPackageNames map[string]struct{}
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("composer"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err = jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package)
	foundDeps := make(map[string][]string)

	p.devPackageNames = make(map[string]struct{})

	for _, pkg := range lockFile.DevPackageNames {
		p.devPackageNames[pkg] = struct{}{}
	}

	p.populateDeps(lockFile.Packages, pkgs, foundDeps, false)
	p.populateDeps(lockFile.DevPackages, pkgs, foundDeps, true)

	// clean up deps with no metadata
	// this is to handle cases where a package is part of require but we have not explicit entry with metadata for the same
	for key, lib := range pkgs {
		if len(lib.Name) == 0 {
			delete(pkgs, key)
		}
	}

	// fill deps versions
	var deps ftypes.Dependencies
	for pkgID, depsOn := range foundDeps {
		var dependsOn []string
		for _, depName := range depsOn {
			if pkg, ok := pkgs[depName]; ok {
				dependsOn = append(dependsOn, pkg.ID)
				continue
			}
			p.logger.Debug("Unable to find version", log.String("name", depName))
		}
		sort.Strings(dependsOn)
		deps = append(deps, ftypes.Dependency{
			ID:        pkgID,
			DependsOn: dependsOn,
		})
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)

	return pkgSlice, deps, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *packageInfo) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

// licenses returns slice of licenses from string, string with separators (`or`, `and`, etc.) or string array
// cf. https://getcomposer.org/doc/04-schema.md#license
func licenses(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return licensing.SplitLicenses(v)
		}
	case []any:
		var lics []string
		for _, l := range v {
			if lic, ok := l.(string); ok {
				lics = append(lics, lic)
			}
		}
		return lics
	}
	return nil
}

func (p *Parser) populateDeps(packages []packageInfo, libs map[string]ftypes.Package, foundDeps map[string][]string, isDev bool) {
	for _, pkg := range packages {
		_, ok := p.devPackageNames[pkg.Name]
		isDev = isDev || ok
		lib := ftypes.Package{
			ID:       dependency.ID(ftypes.Composer, pkg.Name, pkg.Version),
			Name:     pkg.Name,
			Version:  pkg.Version,
			Licenses: pkg.License,
			Locations: []ftypes.Location{
				{
					StartLine: pkg.StartLine,
					EndLine:   pkg.EndLine,
				},
			},
			Dev: isDev,
		}
		if val, ok := libs[lib.Name]; ok {
			lib.Indirect = val.Indirect
		}
		libs[lib.Name] = lib

		var dependsOn []string
		for depName := range pkg.Require {
			// Require field includes required php version, skip this
			// Also skip PHP extensions
			if depName == "php" || strings.HasPrefix(depName, "ext") {
				continue
			}
			dependsOn = append(dependsOn, depName) // field uses range of versions, so later we will fill in the versions from the libraries
			if val, ok := libs[depName]; ok {
				val.Indirect = true
				libs[depName] = val
			} else {
				libs[depName] = ftypes.Package{
					Indirect: true,
				}
			}
		}
		if len(dependsOn) > 0 {
			foundDeps[lib.ID] = dependsOn
		}
	}
}
