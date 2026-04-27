package format

import (
	"fmt"
	"sort"
	"strings"

	"github.com/except-pass/clavis/internal/secret"
)

func init() {
	Register("env", &EnvFormatter{})
}

// EnvFormatter outputs secrets as shell export statements.
type EnvFormatter struct{}

func (f *EnvFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	prefix := nameToEnvPrefix(s.Name)

	var lines []string
	keys := sortedKeys(s.Values)
	for _, k := range keys {
		v := s.Values[k]
		envName := prefix + "_" + strings.ToUpper(k)
		escaped := escapeShellValue(v)
		lines = append(lines, fmt.Sprintf("export %s='%s'", envName, escaped))
	}

	return strings.Join(lines, "\n") + "\n", nil
}

// nameToEnvPrefix converts a secret name to an env var prefix.
// prod/influx -> PROD_INFLUX
func nameToEnvPrefix(name string) string {
	s := strings.ReplaceAll(name, "/", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return strings.ToUpper(s)
}

// escapeShellValue escapes single quotes for shell.
func escapeShellValue(s string) string {
	return strings.ReplaceAll(s, "'", "'\\''")
}

// sortedKeys returns map keys in sorted order.
func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
