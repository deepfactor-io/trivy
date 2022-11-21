package spdx

import (
	"io"

	"github.com/spdx/tools-golang/jsonsaver"
	"github.com/spdx/tools-golang/tvsaver"
	"golang.org/x/xerrors"

<<<<<<< HEAD
	ftypes "github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/types"
=======
	"github.com/aquasecurity/trivy/pkg/sbom/spdx"
	"github.com/aquasecurity/trivy/pkg/types"
>>>>>>> fd5cafb26dfebcea6939572098650f79bafb430c
)

type Writer struct {
	output    io.Writer
	version   string
	format    string
	marshaler *spdx.Marshaler
}

func NewWriter(output io.Writer, version string, spdxFormat string) Writer {
	return Writer{
		output:    output,
		version:   version,
		format:    spdxFormat,
		marshaler: spdx.NewMarshaler(),
	}
}

func (w Writer) Write(report types.Report) error {
	spdxDoc, err := w.marshaler.Marshal(report)
	if err != nil {
		return xerrors.Errorf("failed to marshal spdx: %w", err)
	}

	if w.format == "spdx-json" {
		if err := jsonsaver.Save2_2(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx json: %w", err)
		}
	} else {
		if err := tvsaver.Save2_2(spdxDoc, w.output); err != nil {
			return xerrors.Errorf("failed to save spdx tag-value: %w", err)
		}
	}

	return nil
}
