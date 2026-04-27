package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
	"golang.org/x/term"
)

var unlockPassword string

var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault to restore access to lockable secrets",
	Long: `Enter the lock password to unlock the vault. Once unlocked, all secrets
including those marked as lockable become accessible again.`,
	Args: cobra.NoArgs,
	RunE: runUnlock,
}

func init() {
	unlockCmd.Flags().StringVar(&unlockPassword, "password", "", "Lock password (for scripting; prompts if not set)")
	rootCmd.AddCommand(unlockCmd)
}

func runUnlock(cmd *cobra.Command, args []string) error {
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	if !v.IsLocked() {
		return fmt.Errorf("vault is not locked")
	}

	var password string
	if unlockPassword != "" {
		// Use password from flag
		password = unlockPassword
	} else {
		// Prompt for password
		fmt.Print("Enter lock password: ")
		pwBytes, err := term.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		fmt.Println()
		password = string(pwBytes)
	}

	if err := v.Unlock(password); err != nil {
		return err
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Println("Unlocked.")
	return nil
}
