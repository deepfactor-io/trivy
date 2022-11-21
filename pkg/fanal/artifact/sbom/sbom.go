package sbom

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

<<<<<<< HEAD
	"github.com/deepfactor-io/trivy/pkg/attestation"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer"
	"github.com/deepfactor-io/trivy/pkg/fanal/analyzer/config"
	"github.com/deepfactor-io/trivy/pkg/fanal/artifact"
	"github.com/deepfactor-io/trivy/pkg/fanal/cache"
	"github.com/deepfactor-io/trivy/pkg/fanal/handler"
	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/sbom"
	"github.com/deepfactor-io/trivy/pkg/sbom/cyclonedx"
=======
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
>>>>>>> fd5cafb26dfebcea6939572098650f79bafb430c
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(_ context.Context) (types.ArtifactReference, error) {
	f, err := os.Open(a.filePath)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to open sbom file error: %w", err)
	}
	defer f.Close()

	// Format auto-detection
	format, err := sbom.DetectFormat(f)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to detect SBOM format: %w", err)
	}
	log.Logger.Infof("Detected SBOM format: %s", format)

	bom, err := sbom.Decode(f, format)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("SBOM decode error: %w", err)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            bom.OS,
		PackageInfos:  bom.Packages,
		Applications:  bom.Applications,
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	var artifactType types.ArtifactType
	switch format {
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML, sbom.FormatAttestCycloneDXJSON:
		artifactType = types.ArtifactCycloneDX
	case sbom.FormatSPDXTV, sbom.FormatSPDXJSON:
		artifactType = types.ArtifactSPDX

	}

	return types.ArtifactReference{
		Name:    a.filePath,
		Type:    artifactType,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},

		// Keep an original report
		CycloneDX: bom.CycloneDX,
	}, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func (a Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}
