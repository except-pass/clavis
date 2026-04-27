package format

import (
	"fmt"

	"github.com/except-pass/clavis/internal/secret"
)

// Formatter formats a secret for output.
type Formatter interface {
	// Format returns the formatted output.
	// outputPath is used by file-based formatters (e.g., files).
	Format(s *secret.Secret, outputPath string) (string, error)
}

var registry = make(map[string]Formatter)

// Register adds a formatter to the registry.
func Register(name string, f Formatter) {
	registry[name] = f
}

// Get returns a formatter by name.
// Checks built-in formatters first, then plugins.
func Get(name string) (Formatter, error) {
	if f, ok := registry[name]; ok {
		return f, nil
	}

	// Try plugin
	plugin, err := LoadPlugin(name)
	if err != nil {
		return nil, fmt.Errorf("formatter %q not found: %w", name, err)
	}
	return plugin, nil
}

// List returns all registered formatter names.
func List() []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	return names
}
