package vault

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/secret"
	"golang.org/x/crypto/bcrypt"
)

// Vault holds all secrets.
type Vault struct {
	Version  int              `json:"version"`
	Secrets  []*secret.Secret `json:"secrets"`
	LockHash string           `json:"lock_hash,omitempty"`
}

// IsLocked returns true if the vault has a lock password set.
func (v *Vault) IsLocked() bool {
	return v.LockHash != ""
}

// Lock sets the vault lock with the given password.
func (v *Vault) Lock(password string) error {
	if v.IsLocked() {
		return errors.New("vault is already locked")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	v.LockHash = string(hash)
	return nil
}

// Unlock verifies the password and clears the lock.
func (v *Vault) Unlock(password string) error {
	if !v.IsLocked() {
		return errors.New("vault is not locked")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(v.LockHash), []byte(password)); err != nil {
		return errors.New("incorrect password")
	}
	v.LockHash = ""
	return nil
}

// New creates a new empty vault.
func New() *Vault {
	return &Vault{
		Version: config.VaultVersion,
		Secrets: make([]*secret.Secret, 0),
	}
}

// Load reads and decrypts a vault from disk.
func Load(vaultPath, identityPath string) (*Vault, error) {
	ciphertext, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("reading vault: %w", err)
	}

	plaintext, err := Decrypt(ciphertext, identityPath)
	if err != nil {
		return nil, fmt.Errorf("decrypting vault: %w", err)
	}

	var v Vault
	if err := json.Unmarshal(plaintext, &v); err != nil {
		return nil, fmt.Errorf("parsing vault: %w", err)
	}

	return &v, nil
}

// Save encrypts and writes the vault to disk.
func (v *Vault) Save(vaultPath, pubPath string) error {
	plaintext, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling vault: %w", err)
	}

	ciphertext, err := Encrypt(plaintext, pubPath)
	if err != nil {
		return fmt.Errorf("encrypting vault: %w", err)
	}

	if err := os.WriteFile(vaultPath, ciphertext, 0644); err != nil {
		return fmt.Errorf("writing vault: %w", err)
	}

	return nil
}

// Get retrieves a secret by name.
func (v *Vault) Get(name string) (*secret.Secret, bool) {
	for _, s := range v.Secrets {
		if s.Name == name {
			return s, true
		}
	}
	return nil, false
}

// Add adds a secret to the vault. Replaces if name exists.
func (v *Vault) Add(s *secret.Secret) {
	for i, existing := range v.Secrets {
		if existing.Name == s.Name {
			v.Secrets[i] = s
			return
		}
	}
	v.Secrets = append(v.Secrets, s)
}

// Remove removes a secret by name.
func (v *Vault) Remove(name string) bool {
	for i, s := range v.Secrets {
		if s.Name == name {
			v.Secrets = append(v.Secrets[:i], v.Secrets[i+1:]...)
			return true
		}
	}
	return false
}

// List returns secrets matching the given tag filters (AND logic).
// If filters is nil or empty, returns all secrets.
func (v *Vault) List(filters map[string]string) []*secret.Secret {
	if len(filters) == 0 {
		return v.Secrets
	}

	var result []*secret.Secret
	for _, s := range v.Secrets {
		match := true
		for cat, val := range filters {
			if !s.HasTag(cat, val) {
				match = false
				break
			}
		}
		if match {
			result = append(result, s)
		}
	}
	return result
}
