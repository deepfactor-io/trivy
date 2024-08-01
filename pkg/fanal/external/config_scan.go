package external

import (
	"context"
	"errors"

	"github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/applier"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/artifact"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/artifact/local"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/cache"
	"github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/v3/pkg/misconf"

	_ "github.com/deepfactor-io/trivy/v3/pkg/fanal/analyzer/config/all"
)

type ConfigScanner struct {
	cache         cache.FSCache
	policyPaths   []string
	dataPaths     []string
	namespaces    []string
	allowEmbedded bool
}

func NewConfigScanner(cacheDir string, policyPaths, dataPaths, namespaces []string, allowEmbedded bool) (*ConfigScanner, error) {
	// Initialize local cache
	cacheClient, err := cache.NewFSCache(cacheDir)
	if err != nil {
		return nil, err
	}

	return &ConfigScanner{
		cache:         cacheClient,
		policyPaths:   policyPaths,
		dataPaths:     dataPaths,
		namespaces:    namespaces,
		allowEmbedded: allowEmbedded,
	}, nil
}

func (s ConfigScanner) Scan(dir string) ([]types.Misconfiguration, error) {
	art, err := local.NewArtifact(dir, s.cache, artifact.Option{
		MisconfScannerOption: misconf.ScannerOption{
			PolicyPaths:              s.policyPaths,
			DataPaths:                s.dataPaths,
			Namespaces:               s.namespaces,
			DisableEmbeddedPolicies:  !s.allowEmbedded,
			DisableEmbeddedLibraries: !s.allowEmbedded,
		},
	})
	if err != nil {
		return nil, err
	}

	// Scan config files
	result, err := art.Inspect(context.Background())
	if err != nil {
		return nil, err
	}

	// Merge layers
	a := applier.NewApplier(s.cache)
	mergedLayer, err := a.ApplyLayers(result.ID, result.BlobIDs)
	if !errors.Is(err, analyzer.ErrUnknownOS) && !errors.Is(err, analyzer.ErrNoPkgsDetected) {
		return nil, err
	}

	// Do not assert successes and layer
	for i := range mergedLayer.Misconfigurations {
		mergedLayer.Misconfigurations[i].Layer = types.Layer{}
	}

	return mergedLayer.Misconfigurations, nil
}

func (s ConfigScanner) Close() error {
	return s.cache.Close()
}
