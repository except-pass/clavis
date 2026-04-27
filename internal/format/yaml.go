package format

import (
	"github.com/except-pass/clavis/internal/secret"
	"gopkg.in/yaml.v3"
)

func init() {
	Register("yaml", &YAMLFormatter{})
}

// YAMLFormatter outputs secrets as YAML.
type YAMLFormatter struct{}

func (f *YAMLFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	data, err := yaml.Marshal(s.Values)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
