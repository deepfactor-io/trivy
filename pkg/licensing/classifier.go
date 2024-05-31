package licensing

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/xerrors"

	"github.com/deepfactor-io/trivy/pkg/fanal/types"
	"github.com/deepfactor-io/trivy/pkg/log"
)

var (
	cf             *classifier.Classifier
	classifierOnce sync.Once
	m              sync.Mutex
)

func initGoogleClassifier() error {
	// Initialize the default classifier once.
	// This loading is expensive and should be called only when the license classification is needed.
	var err error
	classifierOnce.Do(func() {
		log.Logger.Debug("Loading the default license classifier...")
		cf, err = assets.DefaultClassifier()
	})
	return err
}

// Classify detects and classifies the license found in a file
func Classify(filePath string, r io.Reader, confidenceLevel float64) (*types.LicenseFile, error) {
	content, err := io.ReadAll(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to read a license file %q: %w", filePath, err)
	}
	if err = initGoogleClassifier(); err != nil {
		return nil, err
	}

	var findings types.LicenseFindings
	var matchType types.LicenseType
	seen := make(map[string]struct{})

	// cf.Match is not thread safe
	m.Lock()

	// Use 'github.com/google/licenseclassifier' to find licenses
	normalizedFileContent := cf.Normalize(content)
	result := cf.Match(normalizedFileContent)

	m.Unlock()

	for _, match := range result.Matches {
		if match.Confidence <= confidenceLevel {
			continue
		}
		if _, ok := seen[match.Name]; ok {
			continue
		}

		seen[match.Name] = struct{}{}

		switch match.MatchType {
		case "Header":
			matchType = types.LicenseTypeHeader
		case "License":
			matchType = types.LicenseTypeFile
		}

		licenseLink := fmt.Sprintf("https://spdx.org/licenses/%s.html", match.Name)

		// get the license text from the match findings
		licenseText := getLicenseText(&normalizedFileContent, match.StartLine, match.EndLine)

		// TODO extract copyright text from license text using regex parse
		// copyrightText := ""

		findings = append(findings, types.LicenseFinding{
			Name:        match.Name,
			Confidence:  match.Confidence,
			Link:        licenseLink,
			LicenseText: licenseText,
		})
	}

	sort.Sort(findings)
	return &types.LicenseFile{
		Type:     matchType,
		FilePath: filePath,
		Findings: findings,
	}, nil
}

// gets the license text found in the file content from given start and end lines
func getLicenseText(fileContent *[]byte, startLine, endLine int) *string {
	scanner := bufio.NewScanner(bytes.NewReader(*fileContent))
	currentLine := 1

	var licenseText string
	var builder strings.Builder

	for scanner.Scan() {
		if currentLine >= startLine && currentLine <= endLine {
			line := scanner.Text()
			line = strings.TrimPrefix(line, "//")
			builder.WriteString(line)
			builder.WriteString("\n")
		}
		if currentLine > endLine {
			break
		}
		currentLine++
	}

	licenseText = builder.String()
	return &licenseText
}
