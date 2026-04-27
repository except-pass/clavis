package main

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var tagsCmd = &cobra.Command{
	Use:   "tags [category]",
	Short: "Discover tags by category",
	Long: `List all tag categories and values, or values for a specific category.
Shows counts for each tag value, sorted by frequency.

Examples:
  clavis tags           # all categories with values
  clavis tags env       # just env values: prod (19), dev (8), ...
  clavis tags service   # just service values
  clavis tags type      # just type values`,
	RunE: runTags,
}

func init() {
	rootCmd.AddCommand(tagsCmd)
}

func runTags(cmd *cobra.Command, args []string) error {
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	// Collect all tags by category
	tagsByCategory := make(map[string]map[string]int) // category -> value -> count
	secrets := v.List(nil)

	for _, s := range secrets {
		for cat, val := range s.Tags {
			if tagsByCategory[cat] == nil {
				tagsByCategory[cat] = make(map[string]int)
			}
			tagsByCategory[cat][val]++
		}
	}

	// If a category is specified, show only values for that category
	if len(args) > 0 {
		category := args[0]
		values, ok := tagsByCategory[category]
		if !ok {
			return fmt.Errorf("no tags found for category %q", category)
		}

		// Sort values by count (descending), then alphabetically
		type valCount struct {
			val   string
			count int
		}
		sorted := make([]valCount, 0, len(values))
		for val, count := range values {
			sorted = append(sorted, valCount{val, count})
		}
		sort.Slice(sorted, func(i, j int) bool {
			if sorted[i].count != sorted[j].count {
				return sorted[i].count > sorted[j].count
			}
			return sorted[i].val < sorted[j].val
		})

		for _, vc := range sorted {
			fmt.Printf("%s:%s (%d)\n", category, vc.val, vc.count)
		}
		return nil
	}

	// Show all categories with their values
	categories := make([]string, 0, len(tagsByCategory))
	for cat := range tagsByCategory {
		categories = append(categories, cat)
	}
	sort.Strings(categories)

	for _, cat := range categories {
		values := tagsByCategory[cat]

		// Sort values alphabetically
		vals := make([]string, 0, len(values))
		for val := range values {
			vals = append(vals, val)
		}
		sort.Strings(vals)

		fmt.Printf("%s:\n", cat)
		for _, val := range vals {
			fmt.Printf("  %s (%d)\n", val, values[val])
		}
	}

	return nil
}
