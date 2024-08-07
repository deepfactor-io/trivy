package cache

import (
	"context"
	"crypto/tls"
	"net/http"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/v3/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/v3/pkg/rpc"
	"github.com/deepfactor-io/trivy/v3/pkg/rpc/client"
	rpcCache "github.com/deepfactor-io/trivy/v3/rpc/cache"
)

var _ ArtifactCache = (*RemoteCache)(nil)

type RemoteOptions struct {
	ServerAddr    string
	CustomHeaders http.Header
	Insecure      bool
}

// RemoteCache implements remote cache
type RemoteCache struct {
	ctx    context.Context // for custom header
	client rpcCache.Cache
}

// NewRemoteCache is the factory method for RemoteCache
func NewRemoteCache(opts RemoteOptions) *RemoteCache {
	ctx := client.WithCustomHeaders(context.Background(), opts.CustomHeaders)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.Insecure,
			},
		},
	}
	c := rpcCache.NewCacheProtobufClient(opts.ServerAddr, httpClient)
	return &RemoteCache{
		ctx:    ctx,
		client: c,
	}
}

// PutArtifact sends artifact to remote client
func (c RemoteCache) PutArtifact(imageID string, artifactInfo types.ArtifactInfo) error {
	err := rpc.Retry(func() error {
		var err error
		_, err = c.client.PutArtifact(c.ctx, rpc.ConvertToRPCArtifactInfo(imageID, artifactInfo))
		return err
	})
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

// PutBlob sends blobInfo to remote client
func (c RemoteCache) PutBlob(diffID string, blobInfo types.BlobInfo) error {
	err := rpc.Retry(func() error {
		var err error
		_, err = c.client.PutBlob(c.ctx, rpc.ConvertToRPCPutBlobRequest(diffID, blobInfo))
		return err
	})
	if err != nil {
		return xerrors.Errorf("unable to store cache on the server: %w", err)
	}
	return nil
}

// MissingBlobs fetches missing blobs from RemoteCache
func (c RemoteCache) MissingBlobs(imageID string, layerIDs []string) (bool, []string, error) {
	var layers *rpcCache.MissingBlobsResponse
	err := rpc.Retry(func() error {
		var err error
		layers, err = c.client.MissingBlobs(c.ctx, rpc.ConvertToMissingBlobsRequest(imageID, layerIDs))
		return err
	})
	if err != nil {
		return false, nil, xerrors.Errorf("unable to fetch missing layers: %w", err)
	}
	return layers.MissingArtifact, layers.MissingBlobIds, nil
}

// DeleteBlobs removes blobs by IDs from RemoteCache
func (c RemoteCache) DeleteBlobs(blobIDs []string) error {
	err := rpc.Retry(func() error {
		var err error
		_, err = c.client.DeleteBlobs(c.ctx, rpc.ConvertToDeleteBlobsRequest(blobIDs))
		return err
	})
	if err != nil {
		return xerrors.Errorf("unable to delete blobs on the server: %w", err)
	}
	return nil
}
