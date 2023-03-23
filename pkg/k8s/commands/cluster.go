package commands

import (
	"context"

	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy-kubernetes/pkg/artifacts"
	"github.com/deepfactor-io/trivy-kubernetes/pkg/k8s"
	"github.com/deepfactor-io/trivy-kubernetes/pkg/trivyk8s"
	"github.com/deepfactor-io/trivy/pkg/flag"
	"github.com/deepfactor-io/trivy/pkg/log"
	"github.com/deepfactor-io/trivy/pkg/types"
)

// clusterRun runs scan on kubernetes cluster
func clusterRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}
	var artifacts []*artifacts.Artifact
	var err error
	if opts.Scanners.AnyEnabled(types.MisconfigScanner) && slices.Contains(opts.Components, "infra") {
		artifacts, err = trivyk8s.New(cluster, log.Logger).ListArtifactAndNodeInfo(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts with node info error: %w", err)
		}
	} else {
		artifacts, err = trivyk8s.New(cluster, log.Logger).ListArtifacts(ctx)
		if err != nil {
			return xerrors.Errorf("get k8s artifacts error: %w", err)
		}
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}
