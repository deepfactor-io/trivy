package parser

import "github.com/deepfactor-io/trivy/v3/pkg/iac/scanners/options"

type ConfigurableHelmParser interface {
	options.ConfigurableParser
	SetValuesFile(...string)
	SetValues(...string)
	SetFileValues(...string)
	SetStringValues(...string)
	SetAPIVersions(...string)
	SetKubeVersion(string)
}

func OptionWithValuesFile(paths ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetValuesFile(paths...)
		}
	}
}

func OptionWithValues(values ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetValues(values...)
		}
	}
}

func OptionWithFileValues(values ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetValues(values...)
		}
	}
}

func OptionWithStringValues(values ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetValues(values...)
		}
	}
}

func OptionWithAPIVersions(values ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetAPIVersions(values...)
		}
	}
}

func OptionWithKubeVersion(value string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if helmParser, ok := p.(ConfigurableHelmParser); ok {
			helmParser.SetKubeVersion(value)
		}
	}
}
