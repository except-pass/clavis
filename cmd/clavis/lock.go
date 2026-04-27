package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
	"golang.org/x/term"
)

var lockPassword string

var lockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault to protect lockable secrets",
	Long: `Set a password to lock the vault. While locked, secrets marked as lockable
cannot be retrieved with 'get' or 'show'. Non-lockable secrets remain accessible.

Use 'clavis unlock' to restore access to locked secrets.`,
	Args: cobra.NoArgs,
	RunE: runLock,
}

func init() {
	lockCmd.Flags().StringVar(&lockPassword, "password", "", "Lock password (for scripting; prompts if not set)")
	rootCmd.AddCommand(lockCmd)
}

func runLock(cmd *cobra.Command, args []string) error {
	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	if v.IsLocked() {
		return fmt.Errorf("vault is already locked (use 'clavis unlock' first)")
	}

	// Count lockable secrets
	var lockableCount int
	for _, s := range v.Secrets {
		if s.Lockable {
			lockableCount++
		}
	}
	if lockableCount == 0 {
		fmt.Println("Warning: no secrets are marked as lockable")
	}

	var password string
	if lockPassword != "" {
		// Use password from flag
		password = lockPassword
	} else {
		// Prompt for password
		fmt.Print("Enter lock password: ")
		pwBytes, err := term.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("reading password: %w", err)
		}
		fmt.Println()

		if len(pwBytes) == 0 {
			return fmt.Errorf("password cannot be empty")
		}

		fmt.Print("Confirm password: ")
		confirm, err := term.ReadPassword(0)
		if err != nil {
			return fmt.Errorf("reading confirmation: %w", err)
		}
		fmt.Println()

		if string(pwBytes) != string(confirm) {
			return fmt.Errorf("passwords do not match")
		}
		password = string(pwBytes)
	}

	if err := v.Lock(password); err != nil {
		return fmt.Errorf("locking vault: %w", err)
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Locked. %d lockable secrets are now protected.\n", lockableCount)
	return nil
}
