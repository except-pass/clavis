package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/secret"
	"github.com/except-pass/clavis/internal/tags"
	"github.com/except-pass/clavis/internal/vault"
)

var addTags []string

var addCmd = &cobra.Command{
	Use:   "add <name> [key=value ...]",
	Short: "Add a new secret",
	Long: `Add a new secret with key-value pairs.

If no name is provided, it will be derived from tags.
If no key=value pairs are provided, prompts interactively.`,
	RunE: runAdd,
}

func init() {
	addCmd.Flags().StringArrayVarP(&addTags, "tag", "t", nil, "Tags in category:value format (can be repeated)")
	rootCmd.AddCommand(addCmd)
}

func runAdd(cmd *cobra.Command, args []string) error {
	if len(args) == 0 && len(addTags) == 0 {
		return fmt.Errorf("usage: clavis add <name> [key=value ...] or clavis add --tag env:prod --tag service:x key=value")
	}

	// Load vault
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	// Parse tags
	parsedTags := make(map[string]string)
	for _, t := range addTags {
		cat, val, err := tags.Parse(t)
		if err != nil {
			return fmt.Errorf("invalid tag %q: %w", t, err)
		}
		if !tags.IsSuggestedCategory(cat) {
			fmt.Fprintf(os.Stderr, "Warning: %q is not a suggested category (env, service, type)\n", cat)
		}
		parsedTags[cat] = val
	}

	// Determine name and key=value args
	var name string
	var kvArgs []string

	if len(args) > 0 {
		// Check if first arg is a key=value or a name
		if strings.Contains(args[0], "=") {
			// All args are key=value, derive name from tags
			kvArgs = args
			if len(parsedTags) == 0 {
				return fmt.Errorf("must provide name or --tag flags")
			}
			name = tags.DeriveName(parsedTags)
		} else {
			name = args[0]
			kvArgs = args[1:]
		}
	} else {
		// No positional args, derive name from tags
		name = tags.DeriveName(parsedTags)
	}

	if name == "" {
		return fmt.Errorf("could not determine secret name")
	}

	// Check if secret already exists
	if _, exists := v.Get(name); exists {
		return fmt.Errorf("secret %q already exists (use 'clavis set' to update)", name)
	}

	// Create secret
	s := secret.New(name)
	for cat, val := range parsedTags {
		s.SetTag(cat, val)
	}

	// Parse key=value pairs
	for _, kv := range kvArgs {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid key=value: %q", kv)
		}
		s.Set(parts[0], parts[1])
	}

	// If no values provided, prompt interactively
	if len(s.Values) == 0 {
		fmt.Println("Enter key=value pairs (empty line to finish):")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				break
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				fmt.Fprintf(os.Stderr, "Invalid format, use key=value: %q\n", line)
				continue
			}
			s.Set(parts[0], parts[1])
		}
	}

	if len(s.Values) == 0 {
		return fmt.Errorf("no values provided")
	}

	// Add and save
	v.Add(s)
	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Added secret: %s\n", name)
	return nil
}
