package terraform

import (
	"io/fs"
	"strings"

	"github.com/deepfactor-io/trivy/v3/pkg/iac/scan"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/options"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/terraform/executor"
	"github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/terraform/parser"
)

type ConfigurableTerraformScanner interface {
	options.ConfigurableScanner
	SetForceAllDirs(bool)
	AddExecutorOptions(options ...executor.Option)
	AddParserOptions(options ...options.ParserOption)
}

func ScannerWithTFVarsPaths(paths ...string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithTFVarsPaths(paths...))
		}
	}
}

func ScannerWithWorkspaceName(name string) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithWorkspaceName(name))
			tf.AddExecutorOptions(executor.OptionWithWorkspaceName(name))
		}
	}
}

func ScannerWithAllDirectories(all bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.SetForceAllDirs(all)
		}
	}
}

func ScannerWithSkipDownloaded(skip bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if !skip {
			return
		}
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddExecutorOptions(executor.OptionWithResultsFilter(func(results scan.Results) scan.Results {
				for i, result := range results {
					prefix := result.Range().GetSourcePrefix()
					if prefix != "" && !strings.HasPrefix(prefix, ".") {
						results[i].OverrideStatus(scan.StatusIgnored)
					}
				}
				return results
			}))
		}
	}
}

func ScannerWithDownloadsAllowed(allowed bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithDownloads(allowed))
		}
	}
}

func ScannerWithSkipCachedModules(b bool) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithSkipCachedModules(b))
		}
	}
}

func ScannerWithConfigsFileSystem(fsys fs.FS) options.ScannerOption {
	return func(s options.ConfigurableScanner) {
		if tf, ok := s.(ConfigurableTerraformScanner); ok {
			tf.AddParserOptions(parser.OptionWithConfigsFS(fsys))
		}
	}
}
