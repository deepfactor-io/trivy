package commands

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy-kubernetes/pkg/k8s"
	"github.com/deepfactor-io/trivy-kubernetes/pkg/trivyk8s"
	"github.com/deepfactor-io/trivy/pkg/flag"
	"github.com/deepfactor-io/trivy/pkg/log"
)

// namespaceRun runs scan on kubernetes cluster
func namespaceRun(ctx context.Context, opts flag.Options, cluster k8s.Cluster) error {
	if err := validateReportArguments(opts); err != nil {
		return err
	}

	trivyk8s := trivyk8s.New(cluster, log.Logger).Namespace(getNamespace(opts, cluster.GetCurrentNamespace()))

	artifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	runner := newRunner(opts, cluster.GetCurrentContext())
	return runner.run(ctx, artifacts)
}

func getNamespace(opts flag.Options, currentNamespace string) string {
	if len(opts.K8sOptions.Namespace) > 0 {
		return opts.K8sOptions.Namespace
	}

	return currentNamespace
}
