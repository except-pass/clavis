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

// AnyLocked reports whether any secret is currently locked.
func (v *Vault) AnyLocked() bool {
	for _, s := range v.Secrets {
		if s.Locked {
			return true
		}
	}
	return false
}

// setPassword establishes the shared lock password for the vault.
func (v *Vault) setPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hashing password: %w", err)
	}
	v.LockHash = string(hash)
	return nil
}

// verifyPassword checks a password against the shared lock hash.
func (v *Vault) verifyPassword(password string) error {
	if err := bcrypt.CompareHashAndPassword([]byte(v.LockHash), []byte(password)); err != nil {
		return errors.New("incorrect password")
	}
	return nil
}

// LockSecret locks a single secret. On the first lock in a vault with no
// password, the given password becomes the shared lock password; on later
// locks the password is verified against it.
func (v *Vault) LockSecret(name, password string) error {
	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}
	if s.Locked {
		return fmt.Errorf("secret %q is already locked", name)
	}
	if v.IsLocked() {
		if err := v.verifyPassword(password); err != nil {
			return err
		}
	} else {
		if err := v.setPassword(password); err != nil {
			return err
		}
	}
	s.Locked = true
	return nil
}

// UnlockSecret unlocks a single secret after verifying the shared password.
// When no secrets remain locked, the shared password is cleared.
func (v *Vault) UnlockSecret(name, password string) error {
	if !v.IsLocked() {
		return errors.New("vault is not locked")
	}
	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}
	if !s.Locked {
		return fmt.Errorf("secret %q is not locked", name)
	}
	if err := v.verifyPassword(password); err != nil {
		return err
	}
	s.Locked = false
	if !v.AnyLocked() {
		v.LockHash = ""
	}
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

	if v.Version < config.VaultVersion {
		if err := migrateToV3(plaintext, &v); err != nil {
			return nil, fmt.Errorf("migrating vault: %w", err)
		}
	}

	return &v, nil
}

// migrateToV3 upgrades a pre-v3 vault to per-secret lock state. Before v3,
// locking was all-or-nothing: a secret was locked iff the vault had a lock
// password AND the secret carried the (now removed) "lockable" flag. This
// recovers that flag from the raw plaintext and sets per-secret Locked
// accordingly. If nothing ends up locked, the shared password is cleared so no
// orphan hash lingers. The migrated state persists on the next Save.
func migrateToV3(plaintext []byte, v *Vault) error {
	type legacySecret struct {
		Name     string `json:"name"`
		Lockable bool   `json:"lockable"`
	}
	type legacyVault struct {
		Secrets []legacySecret `json:"secrets"`
	}

	var legacy legacyVault
	if err := json.Unmarshal(plaintext, &legacy); err != nil {
		return fmt.Errorf("reading legacy lock state: %w", err)
	}

	hadPassword := v.LockHash != ""
	lockable := make(map[string]bool, len(legacy.Secrets))
	for _, ls := range legacy.Secrets {
		lockable[ls.Name] = ls.Lockable
	}

	for _, s := range v.Secrets {
		s.Locked = hadPassword && lockable[s.Name]
	}

	if !v.AnyLocked() {
		v.LockHash = ""
	}

	v.Version = config.VaultVersion
	return nil
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
			// Removing the last locked secret would orphan the shared lock
			// password; keep IsLocked() consistent with AnyLocked().
			if !v.AnyLocked() {
				v.LockHash = ""
			}
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
