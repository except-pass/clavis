package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var (
	unlockPassword string
	unlockAll      bool
)

var unlockCmd = &cobra.Command{
	Use:   "unlock [name]",
	Short: "Unlock one or more secrets to restore access",
	Long: `Enter the shared lock password to unlock secrets. Unlocking the last
locked secret clears the shared password.

Examples:
  clavis unlock prod/mysql        # unlock a single secret
  clavis unlock --all             # unlock every locked secret`,
	Args: cobra.MaximumNArgs(1),
	RunE: runUnlock,
}

func init() {
	unlockCmd.Flags().StringVar(&unlockPassword, "password", "", "Lock password (for scripting; prompts if not set)")
	unlockCmd.Flags().BoolVar(&unlockAll, "all", false, "Unlock every locked secret")
	rootCmd.AddCommand(unlockCmd)
}

func runUnlock(cmd *cobra.Command, args []string) error {
	if !exactlyOneSelector(len(args) == 1, unlockAll, false) {
		return fmt.Errorf("specify a secret name or --all")
	}

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	if !v.IsLocked() {
		return fmt.Errorf("no secrets are locked")
	}

	targets, err := resolveTargets(v, args, unlockAll, "")
	if err != nil {
		return err
	}

	password := unlockPassword
	if password == "" {
		password, err = promptPassword("Enter lock password: ")
		if err != nil {
			return err
		}
	}

	unlocked := 0
	for _, s := range targets {
		if unlockAll && !s.Locked {
			continue // idempotent for bulk operations
		}
		if err := v.UnlockSecret(s.Name, password); err != nil {
			return err
		}
		unlocked++
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Unlocked %d secret(s).\n", unlocked)
	return nil
}
