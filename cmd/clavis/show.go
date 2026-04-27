package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var showReveal bool

var showCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show full details of a secret",
	Long: `Show metadata and values for a secret.

Values are truncated by default to avoid accidental exposure.
Use --reveal to show full values, or use 'clavis get' for scripting.

Examples:
  clavis show prod/mydb              # truncated values
  clavis show prod/mydb --reveal     # full values
  clavis get prod/mydb --format=json # full values (for scripts)`,
	Args: cobra.ExactArgs(1),
	RunE: runShow,
}

func init() {
	showCmd.Flags().BoolVarP(&showReveal, "reveal", "r", false, "Show full values (not truncated)")
	rootCmd.AddCommand(showCmd)
}

func runShow(cmd *cobra.Command, args []string) error {
	name := args[0]

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

	fmt.Printf("Name: %s\n", s.Name)
	fmt.Printf("Created: %s\n", s.Created.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("Modified: %s\n", s.Modified.Format("2006-01-02 15:04:05 UTC"))

	if len(s.Tags) > 0 {
		fmt.Println("\nTags:")
		tagKeys := make([]string, 0, len(s.Tags))
		for k := range s.Tags {
			tagKeys = append(tagKeys, k)
		}
		sort.Strings(tagKeys)
		for _, k := range tagKeys {
			fmt.Printf("  %s: %s\n", k, s.Tags[k])
		}
	}

	if len(s.Values) > 0 {
		fmt.Println("\nValues:")
		valKeys := make([]string, 0, len(s.Values))
		for k := range s.Values {
			valKeys = append(valKeys, k)
		}
		sort.Strings(valKeys)
		for _, k := range valKeys {
			val := s.Values[k]
			// Truncate long values unless --reveal
			if !showReveal && len(val) > 40 {
				if strings.Contains(val, "\n") {
					// Multiline (keys, certs)
					lines := strings.Split(val, "\n")
					val = lines[0] + "\n  ... (" + fmt.Sprintf("%d", len(lines)) + " lines)"
				} else {
					val = val[:12] + "..." + val[len(val)-4:]
				}
			}
			fmt.Printf("  %s: %s\n", k, val)
		}
	}

	return nil
}
