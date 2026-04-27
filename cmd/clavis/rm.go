package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var rmCmd = &cobra.Command{
	Use:   "rm <name>[.key]",
	Short: "Remove a secret or a key from a secret",
	Args:  cobra.ExactArgs(1),
	RunE:  runRm,
}

func init() {
	rootCmd.AddCommand(rmCmd)
}

func runRm(cmd *cobra.Command, args []string) error {
	ref := args[0]

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	// Check if removing a key or whole secret
	if idx := strings.LastIndex(ref, "."); idx != -1 {
		name := ref[:idx]
		key := ref[idx+1:]

		s, ok := v.Get(name)
		if !ok {
			return fmt.Errorf("secret not found: %s", name)
		}

		if _, exists := s.Get(key); !exists {
			return fmt.Errorf("key %q not found in secret %q", key, name)
		}

		s.Delete(key)
		fmt.Printf("Removed key %q from %s\n", key, name)
	} else {
		if !v.Remove(ref) {
			return fmt.Errorf("secret not found: %s", ref)
		}
		fmt.Printf("Removed secret: %s\n", ref)
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	return nil
}
