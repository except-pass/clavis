package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var searchReveal bool

var searchCmd = &cobra.Command{
	Use:   "search <pattern>",
	Short: "Search secret names, tags, and values for a pattern",
	Long: `Search across secret names, tags, and values for a substring match.

Searches in order: name, tags, values. Stops at first match per secret.
Tag matches display as: name [category:value]
Value matches display as: name.key

Use --reveal to show the matching value (truncated around match).

Examples:
  clavis search db.example.com      # find by tag or value
  clavis search prod                # find env:prod tags
  clavis search --reveal admin      # show context around match`,
	Args: cobra.ExactArgs(1),
	RunE: runSearch,
}

func init() {
	searchCmd.Flags().BoolVarP(&searchReveal, "reveal", "r", false, "Show value context around match")
	rootCmd.AddCommand(searchCmd)
}

func runSearch(cmd *cobra.Command, args []string) error {
	pattern := strings.ToLower(args[0])

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	secrets := v.List(nil)
	found := 0

	for _, s := range secrets {
		// Search secret name
		nameLower := strings.ToLower(s.Name)
		if strings.Contains(nameLower, pattern) {
			found++
			fmt.Printf("%s\n", s.Name)
			continue // Don't also search values/tags if name matches
		}

		// Search tags
		tagMatched := false
		for category, value := range s.Tags {
			catLower := strings.ToLower(category)
			valLower := strings.ToLower(value)
			if strings.Contains(catLower, pattern) || strings.Contains(valLower, pattern) {
				found++
				fmt.Printf("%s [%s:%s]\n", s.Name, category, value)
				tagMatched = true
				break // One match per secret for tags
			}
		}
		if tagMatched {
			continue
		}

		// Search values
		for key, val := range s.Values {
			valLower := strings.ToLower(val)
			if idx := strings.Index(valLower, pattern); idx != -1 {
				found++
				if searchReveal {
					// Show context around match
					context := extractContext(val, idx, len(pattern), 20)
					fmt.Printf("%s.%s: ...%s...\n", s.Name, key, context)
				} else {
					fmt.Printf("%s.%s\n", s.Name, key)
				}
			}
		}
	}

	if found == 0 {
		return fmt.Errorf("no matches found for %q", args[0])
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "\n%d match(es) found\n", found)
	return nil
}

// extractContext returns a substring centered on the match with context
func extractContext(val string, idx, patternLen, contextLen int) string {
	start := idx - contextLen
	if start < 0 {
		start = 0
	}
	end := idx + patternLen + contextLen
	if end > len(val) {
		end = len(val)
	}

	result := val[start:end]
	// Replace newlines for display
	result = strings.ReplaceAll(result, "\n", "\\n")
	return result
}
