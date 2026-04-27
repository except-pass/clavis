package format

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/except-pass/clavis/internal/secret"
)

func init() {
	Register("files", &FilesFormatter{})
}

// FilesFormatter writes each key as a separate file.
type FilesFormatter struct{}

func (f *FilesFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	if outputPath == "" {
		return "", fmt.Errorf("--output directory required for files format")
	}

	// Create output directory
	if err := os.MkdirAll(outputPath, 0755); err != nil {
		return "", fmt.Errorf("creating output directory: %w", err)
	}

	prefix := nameToEnvPrefix(s.Name)

	var written []string
	keys := sortedKeys(s.Values)
	for _, k := range keys {
		v := s.Values[k]
		fileName := prefix + "_" + strings.ToUpper(k)
		filePath := filepath.Join(outputPath, fileName)

		if err := os.WriteFile(filePath, []byte(v), 0600); err != nil {
			return "", fmt.Errorf("writing %s: %w", fileName, err)
		}
		written = append(written, filePath)
	}

	// Return list of written files
	return fmt.Sprintf("Wrote %d files to %s\n", len(written), outputPath), nil
}
