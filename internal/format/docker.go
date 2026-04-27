package format

import (
	"fmt"
	"strings"

	"github.com/except-pass/clavis/internal/secret"
)

func init() {
	Register("docker", &DockerFormatter{})
}

// DockerFormatter outputs secrets for Docker --env-file.
type DockerFormatter struct{}

func (f *DockerFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	prefix := nameToEnvPrefix(s.Name)

	var lines []string
	keys := sortedKeys(s.Values)
	for _, k := range keys {
		v := s.Values[k]
		envName := prefix + "_" + strings.ToUpper(k)
		lines = append(lines, fmt.Sprintf("%s=%s", envName, v))
	}

	return strings.Join(lines, "\n") + "\n", nil
}
