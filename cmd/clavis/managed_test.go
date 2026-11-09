package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/except-pass/clavis/internal/managed"
	"github.com/except-pass/clavis/internal/secret"
	"github.com/except-pass/clavis/internal/vault"
)

func TestManagedCLI(t *testing.T) {
	// Every identity and value is generated in disposable local fixture homes.
	root := t.TempDir()
	binary := filepath.Join(root, "clavis")
	build := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", binary, ".")
	if err := build.Run(); err != nil {
		t.Fatal("building fixture CLI:", err)
	}
	controller := filepath.Join(root, "controller")
	machine := filepath.Join(root, "machine")
	other := filepath.Join(root, "other")
	for _, dir := range []string{controller, machine, other} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	sourceDir := filepath.Join(controller, ".secrets")
	if err := os.MkdirAll(sourceDir, 0700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(sourceDir, "identity.txt")
	if err := vault.GenerateIdentity(identity, identity+".pub"); err != nil {
		t.Fatal(err)
	}
	source := vault.New()
	for _, name := range []string{"approved/a", "approved/b", "unapproved/third"} {
		s := secret.New(name)
		s.Set("key", "fixture-sensitive-"+name)
		s.SetTag("scope", "fixture")
		source.Add(s)
	}
	locked := secret.New("locked/secret")
	locked.Set("key", "fixture-sensitive-locked")
	source.Add(locked)
	if err := source.LockSecret("locked/secret", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceDir, "vault.age")
	if err := source.Save(sourcePath, identity+".pub"); err != nil {
		t.Fatal(err)
	}
	run := func(home string, args ...string) (string, string, error) {
		t.Helper()
		command := exec.Command(binary, args...)
		command.Env = append(os.Environ(), "HOME="+home)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		// Plaintext is intentionally allowed only for established credential readers.
		if len(args) > 0 && (args[0] == "managed" || args[0] == "export") {
			if strings.Contains(stdout.String()+stderr.String(), "fixture-sensitive-") || strings.Contains(stdout.String()+stderr.String(), "AGE-SECRET-KEY-") {
				t.Fatal("secret/key material in management command output")
			}
		}
		return stdout.String(), stderr.String(), err
	}
	public, _, err := run(machine, "managed", "keygen")
	if err != nil {
		t.Fatal("machine keygen failed")
	}
	again, _, err := run(machine, "managed", "keygen")
	if err != nil || public != again {
		t.Fatal("keygen isn't idempotent")
	}
	recipientFile := filepath.Join(root, "recipient.pub")
	if err := os.WriteFile(recipientFile, []byte(public), 0600); err != nil {
		t.Fatal(err)
	}
	names := filepath.Join(root, "approved.names")
	if err := os.WriteFile(names, []byte("approved/b\napproved/a\napproved/a\n\n"), 0600); err != nil {
		t.Fatal(err)
	}
	encrypted := filepath.Join(root, "snapshot.age")
	exported, _, err := run(controller, "export", "--recipient", recipientFile, "--names-file", names, "--out", encrypted)
	if err != nil {
		t.Fatal("fixture export failed")
	}
	var report managed.Report
	if err := json.Unmarshal([]byte(exported), &report); err != nil || report.Count != 2 {
		t.Fatal("unexpected export report")
	}
	// Verify has no side effects, suitable for an Ansible validation command.
	verified, _, err := run(machine, "managed", "verify", encrypted)
	if err != nil || verified != exported {
		t.Fatal("verify report differs from export")
	}
	if _, err := os.Stat(filepath.Join(machine, ".secrets", "managed", "vault.age")); !os.IsNotExist(err) {
		t.Fatal("verify mutated managed vault")
	}
	installed, _, err := run(machine, "managed", "install", encrypted)
	if err != nil || installed != exported {
		t.Fatal("install report differs from export")
	}
	if _, err := os.Stat(filepath.Join(machine, ".secrets", "vault.age")); !os.IsNotExist(err) {
		t.Fatal("install created user vault")
	}
	value, _, err := run(machine, "get", "approved/a.key")
	if err != nil || value != "fixture-sensitive-approved/a\n" {
		t.Fatal("managed-only offline get failed")
	}
	if _, _, err := run(machine, "get", "unapproved/third.key"); err == nil {
		t.Fatal("unapproved request arrived")
	}
	for _, args := range [][]string{{"list"}, {"list", "scope:fixture", "--verbose"}, {"tags"}, {"show", "approved/a"}, {"search", "approved/"}} {
		if _, _, err := run(machine, args...); err != nil {
			t.Fatal("managed-only read command failed:", args[0])
		}
	}
	if _, _, err := run(other, "managed", "keygen"); err != nil {
		t.Fatal("other keygen failed")
	}
	if _, _, err := run(other, "managed", "install", encrypted); err == nil {
		t.Fatal("wrong recipient installed snapshot")
	}
	// Remove access to the controller source and delivery file during a real CLI
	// get. Existing managed credentials continue to work from local files.
	unavailable := controller + "-unavailable"
	if err := os.Rename(controller, unavailable); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(encrypted, encrypted+".unavailable"); err != nil {
		t.Fatal(err)
	}
	value, _, err = run(machine, "get", "approved/b.key")
	if err != nil || value != "fixture-sensitive-approved/b\n" {
		t.Fatal("controller outage broke managed get")
	}
	if err := os.Rename(unavailable, controller); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(encrypted+".unavailable", encrypted); err != nil {
		t.Fatal(err)
	}
	// Refusals never replace a last-good export or print secret values.
	beforeExport, err := os.ReadFile(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(names, []byte("approved/a\nmissing/name\nlocked/secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, errors, err := run(controller, "export", "--recipient", recipientFile, "--names-file", names, "--out", encrypted)
	if err == nil || !strings.Contains(errors, "missing/name") || !strings.Contains(errors, "locked/secret") {
		t.Fatal("CLI refusal did not report missing and locked names")
	}
	afterExport, err := os.ReadFile(encrypted)
	if err != nil || !bytes.Equal(beforeExport, afterExport) {
		t.Fatal("refused export changed output")
	}
	for _, protected := range []string{sourcePath, identity, identity + ".pub", names, recipientFile} {
		if _, _, err := run(controller, "export", "--recipient", recipientFile, "--names-file", names, "--out", protected); err == nil {
			t.Fatal("export allowed overwriting source input")
		}
	}
	// User-owned collisions win, writes cannot modify the managed snapshot.
	if _, _, err := run(machine, "init"); err != nil {
		t.Fatal("initializing separate local user vault failed")
	}
	localDir := filepath.Join(machine, ".secrets")
	local := vault.New()
	localSecret := secret.New("approved/a")
	localSecret.Set("key", "fixture-local-override")
	local.Add(localSecret)
	unrelated := secret.New("local/unrelated")
	unrelated.Set("key", "fixture-local-preserved")
	local.Add(unrelated)
	kept := secret.New("local/kept")
	kept.Set("key", "fixture-local-preserved")
	local.Add(kept)
	if err := local.Save(filepath.Join(localDir, "vault.age"), filepath.Join(localDir, "identity.txt.pub")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(localDir, "managed", "vault.age"))
	if err != nil {
		t.Fatal(err)
	}
	value, _, err = run(machine, "get", "approved/a.key")
	if err != nil || value != "fixture-local-override\n" {
		t.Fatal("user collision did not win")
	}
	listed, _, err := run(machine, "list")
	if err != nil || !strings.Contains(listed, "approved/a [managed shadowed by user]") {
		t.Fatal("list did not mark shadowed managed entry")
	}
	// A local lock must never fall through to a same-name unlocked managed copy.
	if err := local.LockSecret("approved/a", "fixture-password"); err != nil {
		t.Fatal(err)
	}
	if err := local.Save(filepath.Join(localDir, "vault.age"), filepath.Join(localDir, "identity.txt.pub")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(machine, "get", "approved/a.key"); err == nil {
		t.Fatal("managed fallback bypassed local lock")
	}
	if _, _, err := run(machine, "rm", "local/unrelated"); err != nil {
		t.Fatal("local write failed")
	}
	if _, _, err := run(machine, "rm", "approved/b"); err == nil {
		t.Fatal("write command modified managed-only name")
	}
	after, err := os.ReadFile(filepath.Join(localDir, "managed", "vault.age"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("write changed managed vault")
	}
	// An empty snapshot revokes all managed entries without deleting user secrets.
	if err := os.WriteFile(names, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(controller, "export", "--recipient", strings.TrimSpace(public), "--names-file", names, "--out", encrypted); err != nil {
		t.Fatal("empty export failed")
	}
	if _, _, err := run(machine, "managed", "install", encrypted); err != nil {
		t.Fatal("empty install failed")
	}
	if _, _, err := run(machine, "get", "approved/b.key"); err == nil {
		t.Fatal("withdrawn managed secret still available")
	}
	if _, _, err := run(machine, "show", "approved/a"); err == nil {
		t.Fatal("local lock was lost during managed revocation")
	}
	listed, _, err = run(machine, "list")
	if err != nil || !strings.Contains(listed, "approved/a") || strings.Contains(listed, "managed shadowed") {
		t.Fatal("user secret was deleted by revocation")
	}
	value, _, err = run(machine, "get", "local/kept.key")
	if err != nil || value != "fixture-local-preserved\n" {
		t.Fatal("managed revocation deleted unrelated local secret")
	}
	// Removing the source and transport inputs proves reads are machine-local.
	if err := os.RemoveAll(controller); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(encrypted); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(machine, "list"); err != nil {
		t.Fatal("controller unavailability broke local reads")
	}
}

func TestExportCannotOverwriteSource(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.WriteFile(source, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "alias")
	if err := os.Link(source, link); err != nil {
		t.Fatal(err)
	}
	if !samePath(source, link) || !samePath(source, filepath.Join(root, ".", "source")) {
		t.Fatal("source alias not protected")
	}
	if samePath(source, filepath.Join(root, "new")) {
		t.Fatal("separate output refused")
	}
}
