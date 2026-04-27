package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/except-pass/clavis/internal/secret"
)

func TestGenerateIdentity(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	pubPath := filepath.Join(dir, "identity.txt.pub")

	err := GenerateIdentity(identityPath, pubPath)
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	if _, err := os.Stat(identityPath); os.IsNotExist(err) {
		t.Error("identity file not created")
	}
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		t.Error("public key file not created")
	}

	info, _ := os.Stat(identityPath)
	if info.Mode().Perm() != 0600 {
		t.Errorf("identity file mode = %o, want 0600", info.Mode().Perm())
	}
}

func TestEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	pubPath := filepath.Join(dir, "identity.txt.pub")

	err := GenerateIdentity(identityPath, pubPath)
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	plaintext := []byte(`{"version":1,"secrets":[]}`)

	ciphertext, err := Encrypt(plaintext, pubPath)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, identityPath)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func setupTestVault(t *testing.T) (string, string, string, string) {
	dir := t.TempDir()
	identityPath := filepath.Join(dir, "identity.txt")
	pubPath := filepath.Join(dir, "identity.txt.pub")
	vaultPath := filepath.Join(dir, "vault.age")

	if err := GenerateIdentity(identityPath, pubPath); err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}

	return dir, identityPath, pubPath, vaultPath
}

func TestVaultCreateAndLoad(t *testing.T) {
	_, identityPath, pubPath, vaultPath := setupTestVault(t)

	// Create new vault
	v := New()
	if err := v.Save(vaultPath, pubPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load it back
	loaded, err := Load(vaultPath, identityPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != 2 {
		t.Errorf("Version = %d, want 2", loaded.Version)
	}
	if len(loaded.Secrets) != 0 {
		t.Errorf("Secrets length = %d, want 0", len(loaded.Secrets))
	}
}

func TestVaultAddAndGet(t *testing.T) {
	_, identityPath, pubPath, vaultPath := setupTestVault(t)

	v := New()
	s := secret.New("prod/influx")
	s.Set("username", "admin")
	s.Set("password", "secret123")

	v.Add(s)

	if err := v.Save(vaultPath, pubPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(vaultPath, identityPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	got, ok := loaded.Get("prod/influx")
	if !ok {
		t.Fatal("secret not found")
	}
	if v, _ := got.Get("username"); v != "admin" {
		t.Errorf("username = %q, want admin", v)
	}
}

func TestVaultRemove(t *testing.T) {
	_, identityPath, pubPath, vaultPath := setupTestVault(t)

	v := New()
	v.Add(secret.New("test/secret"))
	v.Remove("test/secret")

	if err := v.Save(vaultPath, pubPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, _ := Load(vaultPath, identityPath)
	if _, ok := loaded.Get("test/secret"); ok {
		t.Error("secret should have been removed")
	}
}

func TestVaultList(t *testing.T) {
	v := New()
	v.Add(secret.New("prod/influx"))
	v.Add(secret.New("dev/mysql"))
	v.Add(secret.New("prod/github"))

	all := v.List(nil)
	if len(all) != 3 {
		t.Errorf("List all = %d, want 3", len(all))
	}

	// Filter by tag
	s1, _ := v.Get("prod/influx")
	s1.SetTag("env", "prod")
	s2, _ := v.Get("dev/mysql")
	s2.SetTag("env", "dev")
	s3, _ := v.Get("prod/github")
	s3.SetTag("env", "prod")

	filtered := v.List(map[string]string{"env": "prod"})
	if len(filtered) != 2 {
		t.Errorf("List filtered = %d, want 2", len(filtered))
	}
}

func TestVaultIsLocked(t *testing.T) {
	v := New()

	// Fresh vault should not be locked
	if v.IsLocked() {
		t.Error("expected fresh vault to not be locked")
	}

	// After locking, should be locked
	if err := v.Lock("password123"); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	if !v.IsLocked() {
		t.Error("expected vault to be locked after Lock()")
	}
}

func TestVaultLockUnlock(t *testing.T) {
	v := New()

	// Lock sets hash
	if err := v.Lock("mypassword"); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	if v.LockHash == "" {
		t.Error("expected LockHash to be set after Lock()")
	}

	// Wrong password should fail
	if err := v.Unlock("wrongpassword"); err == nil {
		t.Error("expected Unlock with wrong password to fail")
	}
	if !v.IsLocked() {
		t.Error("vault should still be locked after wrong password")
	}

	// Correct password should unlock
	if err := v.Unlock("mypassword"); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	if v.LockHash != "" {
		t.Error("expected LockHash to be cleared after Unlock()")
	}
	if v.IsLocked() {
		t.Error("vault should not be locked after Unlock()")
	}
}

func TestVaultLockAlreadyLocked(t *testing.T) {
	v := New()

	if err := v.Lock("password1"); err != nil {
		t.Fatalf("first Lock failed: %v", err)
	}

	// Second lock should fail
	if err := v.Lock("password2"); err == nil {
		t.Error("expected Lock on already locked vault to fail")
	}
}

func TestVaultUnlockWhenNotLocked(t *testing.T) {
	v := New()

	// Unlock on unlocked vault should fail
	if err := v.Unlock("anypassword"); err == nil {
		t.Error("expected Unlock on unlocked vault to fail")
	}
}

func TestVaultLockPersistence(t *testing.T) {
	_, identityPath, pubPath, vaultPath := setupTestVault(t)

	// Create vault, add lockable secret, lock it
	v := New()
	s := secret.New("prod/secret")
	s.Lockable = true
	v.Add(s)

	if err := v.Lock("testpassword"); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if err := v.Save(vaultPath, pubPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load it back and verify lock state persists
	loaded, err := Load(vaultPath, identityPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !loaded.IsLocked() {
		t.Error("expected loaded vault to be locked")
	}

	// Verify lockable field persists
	loadedSecret, ok := loaded.Get("prod/secret")
	if !ok {
		t.Fatal("secret not found")
	}
	if !loadedSecret.Lockable {
		t.Error("expected secret to still be marked as lockable")
	}
}
