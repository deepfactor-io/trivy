package sum

import (
	"bufio"
	"strings"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/v3/pkg/dependency"
	ftypes "github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	xio "github.com/deepfactor-io/trivy/v3/pkg/x/io"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a go.sum file
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var pkgs []ftypes.Package
	uniquePkgs := make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		s := strings.Fields(line)
		if len(s) < 2 {
			continue
		}

		// go.sum records and sorts all non-major versions
		// with the latest version as last entry
		uniquePkgs[s[0]] = strings.TrimSuffix(strings.TrimPrefix(s[1], "v"), "/go.mod")
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}

	for k, v := range uniquePkgs {
		pkgs = append(pkgs, ftypes.Package{
			ID:      dependency.ID(ftypes.GoModule, k, v),
			Name:    k,
			Version: v,
		})
	}

	return pkgs, nil, nil
}
