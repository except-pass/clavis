package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var lockableCmd = &cobra.Command{
	Use:   "lockable <name>",
	Short: "Toggle lockable flag on a secret",
	Long: `Mark or unmark a secret as lockable. Lockable secrets can be protected
by the vault lock, making them inaccessible until unlocked.

Examples:
  clavis lockable prod/mysql    # mark as lockable
  clavis lockable prod/mysql    # run again to unmark`,
	Args: cobra.ExactArgs(1),
	RunE: runLockable,
}

func init() {
	rootCmd.AddCommand(lockableCmd)
}

func runLockable(cmd *cobra.Command, args []string) error {
	name := args[0]

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}

	s.Lockable = !s.Lockable

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	if s.Lockable {
		fmt.Printf("%q marked as lockable\n", name)
	} else {
		fmt.Printf("%q unmarked\n", name)
	}

	return nil
}
