package managed

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/except-pass/clavis/internal/secret"
	"github.com/except-pass/clavis/internal/vault"
)

type fixture struct {
	source    *vault.Vault
	identity  string
	target    string
	recipient *age.X25519Recipient
	out       string
}

func setup(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	identity := filepath.Join(dir, "controller.identity")
	if err := vault.GenerateIdentity(identity, identity+".pub"); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "machine")
	public, err := Keygen(target)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := Recipient(public)
	if err != nil {
		t.Fatal(err)
	}
	source := vault.New()
	for _, name := range []string{"one", "two", "unapproved", "locked"} {
		s := secret.New(name)
		s.Set("key", "fixture-only-"+name)
		source.Add(s)
	}
	if err := source.LockSecret("locked", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	return fixture{source, identity, target, recipient, filepath.Join(dir, "export.age")}
}

func (f fixture) export(t *testing.T, names ...string) Report {
	t.Helper()
	r, err := Export(f.source, f.identity, f.recipient, names, f.out)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFilteredExportAndRecipientIsolation(t *testing.T) {
	f := setup(t)
	r := f.export(t, "two", "one", "one")
	if r.Count != 2 || strings.Join(r.Names, ",") != "one,two" {
		t.Fatal("incorrect export selection")
	}
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	v, installed, err := Load(f.target)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Fingerprint != r.Fingerprint || len(v.Secrets) != 2 || v.LockHash != "" {
		t.Fatal("snapshot metadata/selection mismatch")
	}
	for _, name := range []string{"unapproved", "locked"} {
		if _, exists := v.Get(name); exists {
			t.Fatal("unrequested secret included")
		}
	}
	another := filepath.Join(t.TempDir(), "other-machine")
	if _, err := Keygen(another); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(another, f.out); err == nil {
		t.Fatal("another machine accepted ciphertext")
	}
	if _, err := vault.Decrypt(mustRead(t, f.out), filepath.Join(another, IdentityFile)); err == nil {
		t.Fatal("another identity decrypted ciphertext")
	}
	if bytes.Equal(mustRead(t, f.identity), mustRead(t, filepath.Join(f.target, IdentityFile))) {
		t.Fatal("publisher identity replicated")
	}
	otherRecipient, err := Keygen(another)
	if err != nil {
		t.Fatal(err)
	}
	f.recipient, err = Recipient(otherRecipient)
	if err != nil {
		t.Fatal(err)
	}
	f.export(t, "two")
	if _, err := Install(another, f.out); err != nil {
		t.Fatal(err)
	}
	otherVault, _, err := Load(another)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := otherVault.Get("one"); ok {
		t.Fatal("first machine's extra secret included")
	}
}

func TestRefusedExportPreservesOutput(t *testing.T) {
	f := setup(t)
	f.export(t, "one")
	before := mustRead(t, f.out)
	_, err := Export(f.source, f.identity, f.recipient, []string{"one", "absent", "locked"}, f.out)
	if err == nil || !strings.Contains(err.Error(), `"absent" (missing)`) || !strings.Contains(err.Error(), `"locked" (locked)`) {
		t.Fatal("missing and locked names were not reported")
	}
	if !bytes.Equal(before, mustRead(t, f.out)) {
		t.Fatal("refusal replaced last export")
	}
}

func TestFingerprintRotationRetryAndRevocation(t *testing.T) {
	f := setup(t)
	first := f.export(t, "one", "two")
	ciphertext := mustRead(t, f.out)
	second := f.export(t, "two", "one")
	if first.Fingerprint != second.Fingerprint {
		t.Fatal("fingerprint varies with ordering or encryption randomness")
	}
	if bytes.Equal(ciphertext, mustRead(t, f.out)) {
		t.Fatal("expected randomized age ciphertext")
	}
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.target, VaultFile)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	active := mustRead(t, path)
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !bytes.Equal(active, mustRead(t, path)) {
		t.Fatal("identical content reinstalled")
	}
	s, _ := f.source.Get("one")
	s.Values["key"] = "fixture-only-rotated" // Deliberately leave Modified unchanged.
	third := f.export(t, "one", "two")
	if first.Fingerprint == third.Fingerprint {
		t.Fatal("value rotation without metadata update did not change fingerprint")
	}
	// A machine offline during export keeps its last-good local copy.
	old, _, err := Load(f.target)
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, _ := old.Get("one")
	if oldSecret.Values["key"] == s.Values["key"] {
		t.Fatal("offline machine unexpectedly changed")
	}
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	// Normal later retry converges; there is no controller dependency on Load.
	now, _, err := Load(f.target)
	if err != nil {
		t.Fatal(err)
	}
	newSecret, _ := now.Get("one")
	if newSecret.Values["key"] != s.Values["key"] {
		t.Fatal("retry did not converge")
	}
	f.export(t, "two")
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	revoked, _, err := Load(f.target)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := revoked.Get("one"); ok {
		t.Fatal("withdrawn secret retained")
	}
	f.export(t)
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	empty, _, err := Load(f.target)
	if err != nil || len(empty.Secrets) != 0 {
		t.Fatal("empty approved set did not withdraw all secrets")
	}
}

func TestKeygenConcurrentIdempotentAndPermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "machine")
	var wg sync.WaitGroup
	results := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := Keygen(dir)
			if err != nil {
				t.Error(err)
				return
			}
			results <- r
		}()
	}
	wg.Wait()
	close(results)
	var public string
	for r := range results {
		if public != "" && r != public {
			t.Fatal("concurrent keygen replaced machine identity")
		}
		public = r
	}
	if err := os.Remove(filepath.Join(dir, IdentityFile+".pub")); err != nil {
		t.Fatal(err)
	}
	again, err := Keygen(dir)
	if err != nil || again != public {
		t.Fatal("public file repair changed recipient")
	}
	for path, mode := range map[string]os.FileMode{dir: 0700, filepath.Join(dir, IdentityFile): 0600, filepath.Join(dir, IdentityFile+".pub"): 0600} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Fatal("unsafe managed permissions")
		}
	}
}

func TestInvalidInstallAndTamperingKeepLastGood(t *testing.T) {
	f := setup(t)
	f.export(t, "one")
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.target, VaultFile)
	good := mustRead(t, path)
	ciphertext := mustRead(t, f.out)
	cases := [][]byte{[]byte("not age"), ciphertext[:len(ciphertext)/2], append([]byte(nil), ciphertext...)}
	cases[2][len(cases[2])-1] ^= 1
	for _, data := range cases {
		if err := os.WriteFile(f.out, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(f.target, f.out); err == nil {
			t.Fatal("invalid ciphertext installed")
		}
		if !bytes.Equal(good, mustRead(t, path)) {
			t.Fatal("failed install damaged last-good")
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("installed snapshot permissions unsafe")
	}
}

func TestInvalidSnapshotStructure(t *testing.T) {
	f := setup(t)
	f.export(t, "one")
	payload, err := vault.Decrypt(mustRead(t, f.out), filepath.Join(f.target, IdentityFile))
	if err != nil {
		t.Fatal(err)
	}
	var original snapshot
	if err := json.Unmarshal(payload, &original); err != nil {
		t.Fatal(err)
	}
	mutations := []func(*snapshot){
		func(s *snapshot) { s.Managed.Recipient = "age1-wrong-machine" },
		func(s *snapshot) { s.Managed.Fingerprint = "invalid" },
		func(s *snapshot) { s.LockHash = "fixture-only-lock-hash" },
		func(s *snapshot) { s.Secrets[0].Locked = true },
		func(s *snapshot) { s.Secrets = append(s.Secrets, s.Secrets[0]) },
		func(s *snapshot) { s.Secrets = append(s.Secrets, nil) },
		func(s *snapshot) { s.Version = 999 },
	}
	for _, mutate := range mutations {
		var s snapshot
		if err := json.Unmarshal(payload, &s); err != nil {
			t.Fatal(err)
		}
		mutate(&s)
		invalid, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := vault.Encrypt(invalid, filepath.Join(f.target, IdentityFile+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.out, cipher, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(f.target, f.out); err == nil {
			t.Fatal("invalid structure accepted")
		}
	}
}

func TestConcurrentInstallAndReaders(t *testing.T) {
	f := setup(t)
	f.export(t, "one")
	first := filepath.Join(t.TempDir(), "first.age")
	if err := os.WriteFile(first, mustRead(t, f.out), 0600); err != nil {
		t.Fatal(err)
	}
	f.export(t, "two")
	if _, err := Install(f.target, first); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			file := first
			if i%2 == 0 {
				file = f.out
			}
			if _, err := Install(f.target, file); err != nil {
				t.Error(err)
			}
		}(i)
	}
	for i := 0; i < 30; i++ {
		v, _, err := Load(f.target)
		if err != nil {
			t.Fatal(err)
		}
		if len(v.Secrets) != 1 {
			t.Fatal("partial snapshot observed")
		}
	}
	wg.Wait()
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	v, _, err := Load(f.target)
	if err != nil || v.Secrets[0].Name != "two" {
		t.Fatal("retry after concurrent delivery failed")
	}
}

// The child stops after the production write/fsync step and before rename.
// Killing it proves a real process interruption cannot expose staged bytes.
func TestInterruptedAtomicWrite(t *testing.T) {
	if os.Getenv("CLAVIS_ATOMIC_CHILD") == "1" {
		_, err := prepare(os.Getenv("CLAVIS_ATOMIC_PATH"), []byte("complete fixture replacement"))
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("CLAVIS_ATOMIC_READY"), []byte("ready"), 0600); err != nil {
			os.Exit(3)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.age")
	ready := filepath.Join(dir, "ready")
	good := []byte("last-good fixture ciphertext")
	if err := atomicWrite(path, good); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestInterruptedAtomicWrite$")
	child.Env = append(os.Environ(), "CLAVIS_ATOMIC_CHILD=1", "CLAVIS_ATOMIC_PATH="+path, "CLAVIS_ATOMIC_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach pre-rename boundary")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(good, mustRead(t, path)) {
		t.Fatal("interruption changed active file")
	}
	if err := atomicWrite(path, []byte("retried fixture replacement")); err != nil {
		t.Fatal(err)
	}
	if string(mustRead(t, path)) != "retried fixture replacement" {
		t.Fatal("retry after interruption failed")
	}
}

func TestReportsAndErrorsDoNotContainValuesOrKeys(t *testing.T) {
	f := setup(t)
	r := f.export(t, "one", "two")
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("fixture-only")) || bytes.Contains(data, []byte("AGE-SECRET-KEY")) {
		t.Fatal("sensitive material in report")
	}
	// Malformed identity parser errors must not echo private input.
	privateFixture := "private-fixture-marker-that-must-not-be-logged"
	if err := os.WriteFile(filepath.Join(f.target, IdentityFile), []byte(privateFixture), 0600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(f.target, f.out)
	if err == nil || strings.Contains(err.Error(), privateFixture) {
		t.Fatal("private input leaked in error")
	}
	if _, err = Keygen(f.target); err == nil || strings.Contains(err.Error(), privateFixture) {
		t.Fatal("keygen leaked/replaced bad identity")
	}
}

func TestLegacyLockedNamesRefused(t *testing.T) {
	f := setup(t)
	// Load must migrate the old lockable flag before Export evaluates lock state.
	legacy := []byte(`{"version":2,"lock_hash":"fixture-lock-hash","secrets":[{"name":"old","lockable":true,"values":{"key":"fixture-only-value"}}]}`)
	cipher, err := vault.Encrypt(legacy, f.identity+".pub")
	if err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(t.TempDir(), "vault.age")
	if err := os.WriteFile(sourcePath, cipher, 0600); err != nil {
		t.Fatal(err)
	}
	source, err := vault.Load(sourcePath, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Export(source, f.identity, f.recipient, []string{"old"}, f.out); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal("legacy lock bypassed")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(fmt.Errorf("reading fixture: %w", err))
	}
	return data
}

func TestKeygenDoesNotStrandInstalledSnapshot(t *testing.T) {
	f := setup(t)
	f.export(t, "one")
	if _, err := Install(f.target, f.out); err != nil {
		t.Fatal(err)
	}
	active := mustRead(t, filepath.Join(f.target, VaultFile))
	if err := os.Remove(filepath.Join(f.target, IdentityFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := Keygen(f.target); err == nil {
		t.Fatal("missing identity silently replaced under existing vault")
	}
	if _, err := os.Stat(filepath.Join(f.target, IdentityFile)); !os.IsNotExist(err) {
		t.Fatal("replacement identity was created")
	}
	if !bytes.Equal(active, mustRead(t, filepath.Join(f.target, VaultFile))) {
		t.Fatal("keygen changed deployed vault")
	}
}
