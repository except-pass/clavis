package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/tags"
	"github.com/except-pass/clavis/internal/vault"
)

var tagCmd = &cobra.Command{
	Use:   "tag <name> <category:value>",
	Short: "Add a tag to a secret",
	Args:  cobra.ExactArgs(2),
	RunE:  runTag,
}

var untagCmd = &cobra.Command{
	Use:   "untag <name> <category>",
	Short: "Remove a tag from a secret",
	Args:  cobra.ExactArgs(2),
	RunE:  runUntag,
}

func init() {
	rootCmd.AddCommand(tagCmd)
	rootCmd.AddCommand(untagCmd)
}

func runTag(cmd *cobra.Command, args []string) error {
	name := args[0]
	tagStr := args[1]

	cat, val, err := tags.Parse(tagStr)
	if err != nil {
		return fmt.Errorf("invalid tag: %w", err)
	}

	if !tags.IsSuggestedCategory(cat) {
		fmt.Fprintf(os.Stderr, "Warning: %q is not a suggested category (env, service, type)\n", cat)
	}

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}

	s.SetTag(cat, val)

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Tagged %s with %s:%s\n", name, cat, val)
	return nil
}

func runUntag(cmd *cobra.Command, args []string) error {
	name := args[0]
	category := args[1]

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}

	s.RemoveTag(category)

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Removed tag %q from %s\n", category, name)
	return nil
}
