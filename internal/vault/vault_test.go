package vault

import (
	"encoding/json"
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

	if loaded.Version != 3 {
		t.Errorf("Version = %d, want 3", loaded.Version)
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

// vaultWithSecrets returns a fresh vault holding the named secrets.
func vaultWithSecrets(names ...string) *Vault {
	v := New()
	for _, n := range names {
		v.Add(secret.New(n))
	}
	return v
}

func TestVaultLockSecretIsolatesOthers(t *testing.T) {
	v := vaultWithSecrets("a", "b")

	if v.IsLocked() {
		t.Error("expected fresh vault to not be locked")
	}

	if err := v.LockSecret("a", "pw"); err != nil {
		t.Fatalf("LockSecret failed: %v", err)
	}
	if !v.IsLocked() {
		t.Error("expected shared password to be set after first lock")
	}

	a, _ := v.Get("a")
	b, _ := v.Get("b")
	if !a.Locked {
		t.Error("expected secret a to be locked")
	}
	if b.Locked {
		t.Error("expected secret b to stay unlocked")
	}
}

func TestVaultLockSecretSharedPassword(t *testing.T) {
	v := vaultWithSecrets("a", "b")

	if err := v.LockSecret("a", "pw"); err != nil {
		t.Fatalf("first LockSecret failed: %v", err)
	}

	// Same password locks a second secret.
	if err := v.LockSecret("b", "pw"); err != nil {
		t.Fatalf("second LockSecret with correct password failed: %v", err)
	}

	// A different password is rejected and leaves state unchanged.
	v2 := vaultWithSecrets("a", "b")
	if err := v2.LockSecret("a", "pw"); err != nil {
		t.Fatalf("setup lock failed: %v", err)
	}
	if err := v2.LockSecret("b", "different"); err == nil {
		t.Error("expected LockSecret with wrong password to fail")
	}
	if b, _ := v2.Get("b"); b.Locked {
		t.Error("expected b to remain unlocked after wrong password")
	}
}

func TestVaultLockSecretErrors(t *testing.T) {
	v := vaultWithSecrets("a")

	if err := v.LockSecret("missing", "pw"); err == nil {
		t.Error("expected LockSecret on unknown secret to fail")
	}

	if err := v.LockSecret("a", "pw"); err != nil {
		t.Fatalf("LockSecret failed: %v", err)
	}
	if err := v.LockSecret("a", "pw"); err == nil {
		t.Error("expected LockSecret on already-locked secret to fail")
	}
}

func TestVaultUnlockSecret(t *testing.T) {
	v := vaultWithSecrets("a", "b")
	if err := v.LockSecret("a", "pw"); err != nil {
		t.Fatalf("LockSecret a failed: %v", err)
	}
	if err := v.LockSecret("b", "pw"); err != nil {
		t.Fatalf("LockSecret b failed: %v", err)
	}

	// Wrong password leaves state unchanged.
	if err := v.UnlockSecret("a", "wrong"); err == nil {
		t.Error("expected UnlockSecret with wrong password to fail")
	}
	if a, _ := v.Get("a"); !a.Locked {
		t.Error("expected a to stay locked after wrong password")
	}

	// Unlocking one of several leaves the shared password in place.
	if err := v.UnlockSecret("a", "pw"); err != nil {
		t.Fatalf("UnlockSecret a failed: %v", err)
	}
	if a, _ := v.Get("a"); a.Locked {
		t.Error("expected a to be unlocked")
	}
	if !v.IsLocked() {
		t.Error("expected shared password to persist while b is still locked")
	}

	// Unlocking the last locked secret clears the shared password.
	if err := v.UnlockSecret("b", "pw"); err != nil {
		t.Fatalf("UnlockSecret b failed: %v", err)
	}
	if v.IsLocked() {
		t.Error("expected shared password to clear after last unlock")
	}
}

func TestVaultUnlockSecretErrors(t *testing.T) {
	v := vaultWithSecrets("a")

	// Vault not locked at all.
	if err := v.UnlockSecret("a", "pw"); err == nil {
		t.Error("expected UnlockSecret on unlocked vault to fail")
	}

	if err := v.LockSecret("a", "pw"); err != nil {
		t.Fatalf("LockSecret failed: %v", err)
	}
	if err := v.UnlockSecret("missing", "pw"); err == nil {
		t.Error("expected UnlockSecret on unknown secret to fail")
	}
	// "a" is locked, but unlocking a never-locked sibling requires the sibling to exist.
	v.Add(secret.New("b"))
	if err := v.UnlockSecret("b", "pw"); err == nil {
		t.Error("expected UnlockSecret on a not-locked secret to fail")
	}
}

func TestVaultLockPersistence(t *testing.T) {
	_, identityPath, pubPath, vaultPath := setupTestVault(t)

	v := vaultWithSecrets("prod/secret", "prod/open")
	if err := v.LockSecret("prod/secret", "testpassword"); err != nil {
		t.Fatalf("LockSecret failed: %v", err)
	}

	if err := v.Save(vaultPath, pubPath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(vaultPath, identityPath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !loaded.IsLocked() {
		t.Error("expected loaded vault to be locked")
	}
	locked, ok := loaded.Get("prod/secret")
	if !ok {
		t.Fatal("secret not found")
	}
	if !locked.Locked {
		t.Error("expected secret to still be locked after reload")
	}
	if open, _ := loaded.Get("prod/open"); open.Locked {
		t.Error("expected sibling secret to stay unlocked after reload")
	}
}

func TestMigrateToV3(t *testing.T) {
	// A v2 vault with a lock password and two lockable secrets migrates so
	// exactly those two are locked.
	locked := []byte(`{
		"version": 2,
		"lock_hash": "$2a$10$abcdefghijklmnopqrstuv",
		"secrets": [
			{"name": "a", "lockable": true},
			{"name": "b", "lockable": true},
			{"name": "c", "lockable": false}
		]
	}`)
	var v Vault
	if err := json.Unmarshal(locked, &v); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := migrateToV3(locked, &v); err != nil {
		t.Fatalf("migrateToV3 failed: %v", err)
	}
	if v.Version != 3 {
		t.Errorf("Version = %d, want 3", v.Version)
	}
	if a, _ := v.Get("a"); !a.Locked {
		t.Error("expected a to be locked after migration")
	}
	if b, _ := v.Get("b"); !b.Locked {
		t.Error("expected b to be locked after migration")
	}
	if c, _ := v.Get("c"); c.Locked {
		t.Error("expected non-lockable c to stay unlocked")
	}
	if !v.IsLocked() {
		t.Error("expected lock hash to persist when secrets are locked")
	}
}

func TestMigrateToV3NoPassword(t *testing.T) {
	// A v2 vault with no lock password locks nothing, even if secrets were
	// marked lockable.
	unlocked := []byte(`{
		"version": 2,
		"secrets": [
			{"name": "a", "lockable": true},
			{"name": "b", "lockable": false}
		]
	}`)
	var v Vault
	if err := json.Unmarshal(unlocked, &v); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := migrateToV3(unlocked, &v); err != nil {
		t.Fatalf("migrateToV3 failed: %v", err)
	}
	if v.AnyLocked() {
		t.Error("expected nothing locked when vault had no password")
	}
	if v.IsLocked() {
		t.Error("expected no lock hash")
	}
}

func TestMigrateToV3ClearsOrphanHash(t *testing.T) {
	// A v2 vault with a password but no lockable secrets clears the orphan hash.
	orphan := []byte(`{
		"version": 2,
		"lock_hash": "$2a$10$abcdefghijklmnopqrstuv",
		"secrets": [
			{"name": "a", "lockable": false}
		]
	}`)
	var v Vault
	if err := json.Unmarshal(orphan, &v); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if err := migrateToV3(orphan, &v); err != nil {
		t.Fatalf("migrateToV3 failed: %v", err)
	}
	if v.IsLocked() {
		t.Error("expected orphan lock hash to be cleared")
	}
	if v.AnyLocked() {
		t.Error("expected nothing locked")
	}
}
