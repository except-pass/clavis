package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/secret"
	"github.com/except-pass/clavis/internal/vault"
)

var migrateFrom string

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Import secrets from a KeePassXC vault",
	Long: `Migrate secrets from an existing KeePassXC .kdbx file.

Maps KeePass entries to the new format:
- Path /service/env becomes env/service
- Username, Password, URL fields become values`,
	RunE: runMigrate,
}

func init() {
	migrateCmd.Flags().StringVar(&migrateFrom, "from", "", "Path to KeePassXC .kdbx file")
	migrateCmd.MarkFlagRequired("from")
	rootCmd.AddCommand(migrateCmd)
}

func runMigrate(cmd *cobra.Command, args []string) error {
	// Check kdbx file exists
	if _, err := os.Stat(migrateFrom); os.IsNotExist(err) {
		return fmt.Errorf("KeePass file not found: %s", migrateFrom)
	}

	// Check keepassxc-cli is available
	if _, err := exec.LookPath("keepassxc-cli"); err != nil {
		return fmt.Errorf("keepassxc-cli not found in PATH")
	}

	// Prompt for KeePass password
	fmt.Print("KeePass master password: ")
	var kpPassword string
	fmt.Scanln(&kpPassword)

	// Load or create vault
	var v *vault.Vault
	var err error
	if _, err := os.Stat(config.VaultPath()); os.IsNotExist(err) {
		fmt.Println("Creating new vault...")
		if err := os.MkdirAll(config.SecretsDir(), 0700); err != nil {
			return fmt.Errorf("creating secrets directory: %w", err)
		}
		if err := vault.GenerateIdentity(config.IdentityPath(), config.IdentityPubPath()); err != nil {
			return fmt.Errorf("generating identity: %w", err)
		}
		v = vault.New()
	} else {
		v, err = vault.Load(config.VaultPath(), config.IdentityPath())
		if err != nil {
			return fmt.Errorf("loading vault: %w", err)
		}
	}

	// List all entries from KeePass
	listCmd := exec.Command("keepassxc-cli", "ls", "-R", "-f", migrateFrom)
	listCmd.Stdin = strings.NewReader(kpPassword + "\n")
	listOutput, err := listCmd.Output()
	if err != nil {
		return fmt.Errorf("listing KeePass entries: %w", err)
	}

	var imported, skipped int
	scanner := bufio.NewScanner(strings.NewReader(string(listOutput)))
	for scanner.Scan() {
		entry := strings.TrimSpace(scanner.Text())
		if entry == "" || strings.HasSuffix(entry, "/") {
			continue // Skip groups
		}

		// Get entry details
		showCmd := exec.Command("keepassxc-cli", "show", "-s", migrateFrom, entry)
		showCmd.Stdin = strings.NewReader(kpPassword + "\n")
		showOutput, err := showCmd.Output()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", entry, err)
			skipped++
			continue
		}

		// Parse entry
		s := parseKeePassEntry(entry, string(showOutput))
		if s == nil || len(s.Values) == 0 {
			skipped++
			continue
		}

		v.Add(s)
		imported++
		fmt.Printf("  + %s\n", s.Name)
	}

	// Save vault
	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("\nMigration complete: %d imported, %d skipped\n", imported, skipped)
	return nil
}

func parseKeePassEntry(path, output string) *secret.Secret {
	// Convert path: /service/env -> env/service
	parts := strings.Split(strings.Trim(path, "/"), "/")
	var name string
	if len(parts) >= 2 {
		// Assume last part is env, reverse order
		reversed := make([]string, len(parts))
		for i, p := range parts {
			reversed[len(parts)-1-i] = p
		}
		name = strings.Join(reversed, "/")
	} else {
		name = strings.Join(parts, "/")
	}

	s := secret.New(name)

	// Parse output for fields
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "UserName: ") {
			val := strings.TrimPrefix(line, "UserName: ")
			if val != "" {
				s.Set("username", val)
			}
		} else if strings.HasPrefix(line, "Password: ") {
			val := strings.TrimPrefix(line, "Password: ")
			if val != "" {
				s.Set("password", val)
			}
		} else if strings.HasPrefix(line, "URL: ") {
			val := strings.TrimPrefix(line, "URL: ")
			if val != "" {
				s.Set("url", val)
			}
		}
	}

	// Auto-tag based on path
	if len(parts) >= 1 {
		// First part after reversal is typically env
		env := parts[len(parts)-1]
		if env == "prod" || env == "dev" || env == "staging" {
			s.SetTag("env", env)
		}
	}
	if len(parts) >= 2 {
		s.SetTag("service", parts[0])
	}

	return s
}
