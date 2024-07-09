package licensing

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	classifier "github.com/google/licenseclassifier/v2"
	"github.com/google/licenseclassifier/v2/assets"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
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
	result := cf.Match(cf.Normalize(content))

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

		findings = append(findings, types.LicenseFinding{
			Name:       match.Name,
			Confidence: match.Confidence,
			Link:       licenseLink,
		})
	}
	sort.Sort(findings)
	return &types.LicenseFile{
		Type:     matchType,
		FilePath: filePath,
		Findings: findings,
	}, nil
}

type ClassifierInput struct {
	PkgID               string
	FilePath            string
	Content             []byte
	ConfidenceLevel     float64
	LicenseTextCacheDir string
}

// ClassifyV2 detects and classifies the license found in a file.
// It also extracts the license text for each match, creates and persist them in in given folder
// Each file would be of form <license-text-checksum>.txt
func (input *ClassifierInput) Classify() (*types.LicenseFile, error) {
	if err := initGoogleClassifier(); err != nil {
		return nil, err
	}

	var findings types.LicenseFindings
	var matchType types.LicenseType
	seen := make(map[string]struct{})

	// cf.Match is not thread safe
	m.Lock()

	// Use 'github.com/google/licenseclassifier' to find licenses
	result := cf.Match(cf.Normalize(input.Content))

	m.Unlock()

	for _, match := range result.Matches {
		if match.Confidence <= input.ConfidenceLevel {
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

		// extract & get the checksum and license text for the current match
		textChecksum, licenseText := extractLicenseText(input.Content, match.StartLine, match.EndLine)

		// persist the license text in given folder
		if input.LicenseTextCacheDir != "" && len(licenseText) > 0 {
			go input.persistLicenseText(textChecksum, licenseText)
		}

		// extract copyright text from license text using regex parse
		copyrightText := extractCopyrightFromLicenseText(licenseText)

		findings = append(findings, types.LicenseFinding{
			Name:          match.Name,
			Confidence:    match.Confidence,
			Link:          licenseLink,
			LicenseText:   textChecksum,
			CopyRightText: copyrightText,
		})
	}

	sort.Sort(findings)
	return &types.LicenseFile{
		Type:     matchType,
		FilePath: input.FilePath,
		Findings: findings,
	}, nil
}

// extracts the license text found in the file content from given start and end lines
func extractLicenseText(
	fileContent []byte,
	startLine int,
	endLine int,
) (string, string) {
	scanner := bufio.NewScanner(bytes.NewReader(fileContent))
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

	// replace the newlines and tabs characters
	licenseText = strings.ReplaceAll(licenseText, "\\n", "\n")
	licenseText = strings.ReplaceAll(licenseText, "\\t", "\t")

	return generateChecksum(licenseText), licenseText
}

// generates unique checksum for given text
func generateChecksum(text string) string {
	if len(text) == 0 {
		return ""
	}

	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

func (input *ClassifierInput) persistLicenseText(
	checksum string,
	licenseText string,
) error {
	// <checksum>.txt would be the name of the file where license text is persisted
	licenseTextFilepath := filepath.Join(input.LicenseTextCacheDir, fmt.Sprintf("%s.txt", checksum))

	// persist only when file does not exist
	if _, err := os.Stat(licenseTextFilepath); errors.Is(err, fs.ErrNotExist) {
		bytes, err := convertToUTF8([]byte(licenseText))
		if err != nil {
			return fmt.Errorf("failed to convert given bytes to utf-8 encoded, checksum: %s, err: %s", checksum, err.Error())
		}
		err = os.WriteFile(licenseTextFilepath, bytes, 0644)
		if err != nil {
			fmt.Println("Error! failed to persist license text: err:: ", err.Error())
			return fmt.Errorf("failed to persist license text. (checksum: %s, err: %s)", checksum, err.Error())
		}
	}

	return nil
}

// extracts the copyright text from given license text
func extractCopyrightFromLicenseText(text string) string {
	re := regexp.MustCompile(`(?i)Copyright\s+((\(c\)|©)?\s*\d{4}(?:-\d{4})?\s+.*?)(?:\\n|$)`)
	matches := re.FindAllString(text, -1)
	if len(matches) == 0 {
		return ""
	}

	// if there are multiple matches, we take the last one
	copyrightText := matches[len(matches)-1]

	// trim new line chars if present
	copyrightText = strings.Trim(copyrightText, "\\n")
	return copyrightText
}

func convertToUTF8(input []byte) ([]byte, error) {
	if utf8.Valid(input) {
		return input, nil
	}

	// Create a decoder for the current encoding (e.g., ISO-8859-1)
	decoder := unicode.UTF8.NewDecoder()

	// Create a Reader to transform the input bytes using the decoder
	reader := transform.NewReader(bytes.NewReader(input), decoder)

	// Read and decode the bytes into a new byte slice
	output, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return output, nil
}
