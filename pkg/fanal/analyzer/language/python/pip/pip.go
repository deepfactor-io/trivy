package pip

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/go-dep-parser/pkg/python/pip"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/language"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&pipLibraryAnalyzer{})
}

const version = 1

type pipLibraryAnalyzer struct{}

func (a pipLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(types.Pip, input.FilePath, input.Content, pip.NewParser())
	if err != nil {
		return nil, xerrors.Errorf("unable to parse requirements.txt: %w", err)
	}
	return res, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return strings.HasPrefix(fileName, "req") && strings.HasSuffix(fileName, ".txt")
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
