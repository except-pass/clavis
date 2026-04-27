package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the secrets vault",
	Long:  "Creates ~/.secrets directory, generates an age keypair, and creates an empty vault.",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	secretsDir := config.SecretsDir()
	identityPath := config.IdentityPath()
	pubPath := config.IdentityPubPath()
	vaultPath := config.VaultPath()
	formattersDir := config.FormattersPath()

	// Check if already initialized
	if _, err := os.Stat(vaultPath); err == nil {
		return fmt.Errorf("vault already exists at %s", vaultPath)
	}

	// Create secrets directory
	if err := os.MkdirAll(secretsDir, 0700); err != nil {
		return fmt.Errorf("creating secrets directory: %w", err)
	}
	fmt.Printf("Created %s\n", secretsDir)

	// Create formatters directory
	if err := os.MkdirAll(formattersDir, 0755); err != nil {
		return fmt.Errorf("creating formatters directory: %w", err)
	}
	fmt.Printf("Created %s\n", formattersDir)

	// Generate identity
	if err := vault.GenerateIdentity(identityPath, pubPath); err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}
	fmt.Printf("Generated identity at %s\n", identityPath)

	// Create empty vault
	v := vault.New()
	if err := v.Save(vaultPath, pubPath); err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}
	fmt.Printf("Created vault at %s\n", vaultPath)

	fmt.Println("\nInitialization complete. Add secrets with: clavis add <name> key=value")
	return nil
}
