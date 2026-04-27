package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/tags"
	"github.com/except-pass/clavis/internal/vault"
)

var listShowTags bool
var listVerbose bool

var listCmd = &cobra.Command{
	Use:   "list [tag:value ...]",
	Short: "List secrets, optionally filtered by tags",
	Long: `List all secrets or filter by tags. Multiple tags use AND logic.

Examples:
  clavis list                        # all secrets
  clavis list env:prod               # filter by one tag
  clavis list env:prod type:database # multiple tags (AND)
  clavis list --tags                 # show tags alongside names
  clavis list --verbose              # show names, tags, and keys`,
	RunE: runList,
}

func init() {
	listCmd.Flags().BoolVar(&listShowTags, "tags", false, "Show tags alongside names")
	listCmd.Flags().BoolVarP(&listVerbose, "verbose", "v", false, "Show names, tags, and keys")
	rootCmd.AddCommand(listCmd)
}

func runList(cmd *cobra.Command, args []string) error {
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	// Parse tag filters
	filters := make(map[string]string)
	for _, arg := range args {
		cat, val, err := tags.Parse(arg)
		if err != nil {
			return fmt.Errorf("invalid tag filter %q: %w", arg, err)
		}
		filters[cat] = val
	}

	secrets := v.List(filters)

	// Sort by name
	sort.Slice(secrets, func(i, j int) bool {
		return secrets[i].Name < secrets[j].Name
	})

	isLocked := v.IsLocked()

	for _, s := range secrets {
		// Determine lock indicator for lockable secrets
		var lockIndicator string
		if s.Lockable {
			if isLocked {
				lockIndicator = " \U0001F512" // locked padlock
			} else {
				lockIndicator = " \U0001F513" // unlocked padlock
			}
		}

		if listVerbose {
			fmt.Printf("%s%s\n", s.Name, lockIndicator)
			if len(s.Tags) > 0 {
				tagStrs := make([]string, 0, len(s.Tags))
				for cat, val := range s.Tags {
					tagStrs = append(tagStrs, fmt.Sprintf("%s:%s", cat, val))
				}
				sort.Strings(tagStrs)
				fmt.Printf("  tags: %s\n", strings.Join(tagStrs, ", "))
			}
			if len(s.Values) > 0 {
				keys := make([]string, 0, len(s.Values))
				for k := range s.Values {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				fmt.Printf("  keys: %s\n", strings.Join(keys, ", "))
			}
		} else if listShowTags {
			tagStrs := make([]string, 0, len(s.Tags))
			for cat, val := range s.Tags {
				tagStrs = append(tagStrs, fmt.Sprintf("%s:%s", cat, val))
			}
			sort.Strings(tagStrs)
			if len(tagStrs) > 0 {
				fmt.Printf("%s%s  [%s]\n", s.Name, lockIndicator, strings.Join(tagStrs, ", "))
			} else {
				fmt.Printf("%s%s\n", s.Name, lockIndicator)
			}
		} else {
			fmt.Printf("%s%s\n", s.Name, lockIndicator)
		}
	}

	return nil
}
