package format

import (
	"encoding/json"

	"github.com/except-pass/clavis/internal/secret"
)

func init() {
	Register("json", &JSONFormatter{})
}

// JSONFormatter outputs secrets as JSON.
type JSONFormatter struct{}

func (f *JSONFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	data, err := json.MarshalIndent(s.Values, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}
