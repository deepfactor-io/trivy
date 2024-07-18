package composerjson

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sort"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	xio "github.com/deepfactor-io/trivy/pkg/x/io"
)

type composerJSON struct {
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{}
}

/*
Parse : parses the composer.json file and extracts the packages explicitly requested for installation
Same is used to identify direct dependencies in case of image scans
*/
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var cJSON composerJSON
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err = json.Unmarshal(input, &cJSON); err != nil {
		return nil, nil, xerrors.Errorf("unmarshal error: %w", err)
	}

	libs := map[string]ftypes.Package{}

	for pkg, ver := range cJSON.Require {
		lib := ftypes.Package{
			ID:       pkg,
			Name:     pkg,
			Version:  ver,
			Indirect: false,
			Dev:      false,
		}
		// the key includes dev flag, to handle dev-prod conflict for the same package
		// version does not matter because php allows only 1 version to be installed
		// More over the version in composer.json is not necessarily an exact version
		libs[lib.Name+fmt.Sprint(lib.Dev)] = lib
	}

	for pkg, ver := range cJSON.RequireDev {
		lib := ftypes.Package{
			ID:       pkg,
			Name:     pkg,
			Version:  ver,
			Indirect: false,
			Dev:      true,
		}
		libs[lib.Name+fmt.Sprint(lib.Dev)] = lib
	}
	libSlice := maps.Values(libs)
	sort.Sort(ftypes.Packages(libSlice))

	return libSlice, []ftypes.Dependency{}, nil
}
