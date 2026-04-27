package config

import (
	"os"
	"path/filepath"
)

const (
	DirName         = ".secrets"
	VaultFile       = "vault.age"
	IdentityFile    = "identity.txt"
	IdentityPubFile = "identity.txt.pub"
	FormattersDir   = "formatters"
	VaultVersion    = 2
)

// SecretsDir returns the path to ~/.secrets
func SecretsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, DirName)
}

// VaultPath returns the path to ~/.secrets/vault.age
func VaultPath() string {
	return filepath.Join(SecretsDir(), VaultFile)
}

// IdentityPath returns the path to ~/.secrets/identity.txt
func IdentityPath() string {
	return filepath.Join(SecretsDir(), IdentityFile)
}

// IdentityPubPath returns the path to ~/.secrets/identity.txt.pub
func IdentityPubPath() string {
	return filepath.Join(SecretsDir(), IdentityPubFile)
}

// FormattersPath returns the path to ~/.secrets/formatters
func FormattersPath() string {
	return filepath.Join(SecretsDir(), FormattersDir)
}
