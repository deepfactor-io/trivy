package jar

import (
	"fmt"

	"golang.org/x/xerrors"

	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
)

var ArtifactNotFoundErr = xerrors.New("no artifact found")

type Properties struct {
	GroupID    string
	ArtifactID string
	Version    string
	FilePath   string   // path to file containing these props
	Warnings   []string `json:",omitempty"`
	License    []string
}

func (p Properties) Package() ftypes.Package {
	return ftypes.Package{
		Name:     fmt.Sprintf("%s:%s", p.GroupID, p.ArtifactID),
		Version:  p.Version,
		FilePath: p.FilePath,
		Warnings: []string{},
		Licenses: p.License,
	}
}

func (p Properties) Valid() bool {
	return p.GroupID != "" && p.ArtifactID != "" && p.Version != ""
}

func (p Properties) String() string {
	return fmt.Sprintf("%s:%s:%s", p.GroupID, p.ArtifactID, p.Version)
}
