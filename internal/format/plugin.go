package format

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/secret"
)

// PluginFormatter runs an external script as a formatter.
type PluginFormatter struct {
	path string
}

// LoadPlugin finds and returns a plugin formatter.
func LoadPlugin(name string) (*PluginFormatter, error) {
	formattersDir := config.FormattersPath()
	pluginPath := filepath.Join(formattersDir, name)

	info, err := os.Stat(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("plugin not found: %s", pluginPath)
	}

	// Check if executable
	if info.Mode()&0111 == 0 {
		return nil, fmt.Errorf("plugin not executable: %s", pluginPath)
	}

	return &PluginFormatter{path: pluginPath}, nil
}

// Format runs the plugin and returns its output.
func (p *PluginFormatter) Format(s *secret.Secret, outputPath string) (string, error) {
	// Prepare input JSON
	input := struct {
		Name   string            `json:"name"`
		Tags   map[string]string `json:"tags"`
		Values map[string]string `json:"values"`
	}{
		Name:   s.Name,
		Tags:   s.Tags,
		Values: s.Values,
	}

	inputJSON, err := json.Marshal(input)
	if err != nil {
		return "", fmt.Errorf("marshaling input: %w", err)
	}

	// Build command
	args := []string{}
	if outputPath != "" {
		args = append(args, outputPath)
	}

	cmd := exec.Command(p.path, args...)
	cmd.Stdin = bytes.NewReader(inputJSON)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("plugin error: %s: %s", err, stderr.String())
	}

	return stdout.String(), nil
}
