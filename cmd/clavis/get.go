package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/format"
	"github.com/except-pass/clavis/internal/vault"
)

var getFormat string
var getOutput string

var getCmd = &cobra.Command{
	Use:   "get <name>[.key]",
	Short: "Get a secret or specific key",
	Long: `Retrieve a secret bundle or a specific key within it.

Use dot notation to get a single key value (no formatting, just the raw value).
Use --format to change output format for full bundles.

Examples:
  clavis get prod/influx              # full bundle as env vars
  clavis get prod/influx.password     # just the password value
  clavis get prod/influx --format=json
  clavis get prod/influx --format=docker > .env
  clavis get ssh/mykey.private_key > /tmp/key.pem`,
	Args: cobra.ExactArgs(1),
	RunE: runGet,
}

func init() {
	getCmd.Flags().StringVarP(&getFormat, "format", "f", "env", "Output format (env, json, yaml, docker, files, or plugin name)")
	getCmd.Flags().StringVarP(&getOutput, "output", "o", "", "Output directory (for file-based formats)")
	rootCmd.AddCommand(getCmd)
}

func runGet(cmd *cobra.Command, args []string) error {
	// Parse name and optional key
	ref := args[0]
	var name, key string

	// Split on last dot to get key
	if idx := strings.LastIndex(ref, "."); idx != -1 {
		possibleKey := ref[idx+1:]
		possibleName := ref[:idx]

		// Try with the dot as key separator first
		v, err := vault.Load(config.VaultPath(), config.IdentityPath())
		if err != nil {
			return fmt.Errorf("loading vault: %w", err)
		}

		if s, ok := v.Get(possibleName); ok {
			if _, hasKey := s.Get(possibleKey); hasKey {
				name = possibleName
				key = possibleKey
			}
		}

		// If not found as name.key, treat whole thing as name
		if name == "" {
			if _, ok := v.Get(ref); ok {
				name = ref
			} else {
				// Still try the split version if full name doesn't exist
				name = possibleName
				key = possibleKey
			}
		}
	} else {
		name = ref
	}

	// Load vault
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}

	// Check if secret is locked
	if v.IsLocked() && s.Lockable {
		return fmt.Errorf("secret %q is locked", name)
	}

	// If specific key requested, just print that value
	if key != "" {
		val, ok := s.Get(key)
		if !ok {
			return fmt.Errorf("key %q not found in secret %q", key, name)
		}
		fmt.Println(val)
		return nil
	}

	// Format output
	formatter, err := format.Get(getFormat)
	if err != nil {
		return fmt.Errorf("getting formatter: %w", err)
	}

	output, err := formatter.Format(s, getOutput)
	if err != nil {
		return fmt.Errorf("formatting: %w", err)
	}

	if output != "" {
		fmt.Print(output)
	}

	return nil
}
