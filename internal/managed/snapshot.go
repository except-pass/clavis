package managed

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"filippo.io/age"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

type metadata struct {
	Recipient   string `json:"recipient"`
	Fingerprint string `json:"fingerprint"`
}

type snapshot struct {
	*vault.Vault
	Managed metadata `json:"managed"`
}

// Report contains only public metadata, never values or private key material.
type Report struct {
	Count       int      `json:"count"`
	Names       []string `json:"names"`
	Fingerprint string   `json:"fingerprint"`
}

func stringTrim(data []byte) string { return strings.TrimSpace(string(data)) }

// Recipient accepts one X25519 public recipient or a file containing one.
func Recipient(value string) (*age.X25519Recipient, error) {
	if r, err := age.ParseX25519Recipient(value); err == nil {
		return r, nil
	}
	data, err := os.ReadFile(value)
	if err != nil {
		return nil, fmt.Errorf("recipient must be one X25519 public key or a readable public-key file")
	}
	r, err := age.ParseX25519Recipient(stringTrim(data))
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public recipient")
	}
	return r, nil
}

// Export writes a complete filtered snapshot; any missing or locked request
// aborts the entire export before changing the output. Authorization belongs to
// the caller's inventory policy; names alone never establish authorization.
func Export(source *vault.Vault, sourceIdentity string, recipient *age.X25519Recipient, names []string, out string) (Report, error) {
	// Unknown source versions may use different lock semantics; never bypass
	// protections by interpreting them as the current schema.
	if source.Version != config.VaultVersion {
		return Report{}, fmt.Errorf("cannot export unsupported source vault version")
	}
	filtered := vault.New()
	requested := make(map[string]bool)
	for _, name := range names {
		if name != "" {
			requested[name] = true
		}
	}
	sorted := make([]string, 0, len(requested))
	for name := range requested {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	var refused []string
	for _, name := range sorted {
		s, ok := source.Get(name)
		if !ok {
			refused = append(refused, fmt.Sprintf("%q (missing)", name))
			continue
		}
		if s.Locked {
			refused = append(refused, fmt.Sprintf("%q (locked)", name))
			continue
		}
		filtered.Add(s)
	}
	if len(refused) > 0 {
		return Report{}, fmt.Errorf("export refused: %s", strings.Join(refused, ", "))
	}
	content, err := json.Marshal(filtered)
	if err != nil {
		return Report{}, fmt.Errorf("encoding filtered vault failed")
	}
	keyData, err := os.ReadFile(sourceIdentity)
	if err != nil {
		return Report{}, fmt.Errorf("reading publisher identity: %w", err)
	}
	key, err := age.ParseX25519Identity(stringTrim(keyData))
	if err != nil {
		return Report{}, fmt.Errorf("invalid publisher identity")
	}
	// A keyed digest prevents public reports from becoming an offline oracle for
	// low-entropy values. Include the recipient to scope generations to a machine.
	mac := hmac.New(sha256.New, []byte(key.String()))
	mac.Write([]byte("clavis-managed-v1\x00" + recipient.String() + "\x00"))
	mac.Write(content)
	fingerprint := hex.EncodeToString(mac.Sum(nil))
	payload, err := json.Marshal(snapshot{filtered, metadata{recipient.String(), fingerprint}})
	if err != nil {
		return Report{}, fmt.Errorf("encoding managed snapshot failed")
	}
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, recipient)
	if err != nil {
		return Report{}, fmt.Errorf("creating snapshot encryption failed")
	}
	if _, err = w.Write(payload); err != nil {
		return Report{}, fmt.Errorf("encrypting snapshot failed")
	}
	if err = w.Close(); err != nil {
		return Report{}, fmt.Errorf("finishing snapshot encryption failed")
	}
	if err := atomicWrite(out, ciphertext.Bytes()); err != nil {
		return Report{}, fmt.Errorf("writing export: %w", err)
	}
	return Report{len(sorted), sorted, fingerprint}, nil
}

func decode(data []byte, dir string) (*snapshot, error) {
	id, err := identity(dir)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(data), id)
	if err != nil {
		return nil, fmt.Errorf("snapshot does not decrypt with this machine's identity")
	}
	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("snapshot authentication failed")
	}
	var s snapshot
	// Keep parser diagnostics out of logs; JSON errors may contain input values.
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, fmt.Errorf("invalid managed snapshot JSON")
	}
	if s.Vault == nil || s.Version != config.VaultVersion {
		return nil, fmt.Errorf("unsupported managed vault version")
	}
	if s.Managed.Recipient != id.Recipient().String() {
		return nil, fmt.Errorf("snapshot recipient does not match this machine")
	}
	digest, err := hex.DecodeString(s.Managed.Fingerprint)
	if err != nil || len(digest) != sha256.Size {
		return nil, fmt.Errorf("invalid snapshot fingerprint")
	}
	if s.LockHash != "" {
		return nil, fmt.Errorf("managed snapshot must not contain a lock password")
	}
	seen := make(map[string]bool)
	for _, secret := range s.Secrets {
		if secret == nil || secret.Name == "" {
			return nil, fmt.Errorf("invalid secret in managed snapshot")
		}
		if seen[secret.Name] {
			return nil, fmt.Errorf("duplicate managed secret name")
		}
		if secret.Locked {
			return nil, fmt.Errorf("managed snapshot contains a locked secret")
		}
		seen[secret.Name] = true
	}
	return &s, nil
}

func report(s *snapshot) Report {
	names := make([]string, 0, len(s.Secrets))
	for _, secret := range s.Secrets {
		names = append(names, secret.Name)
	}
	sort.Strings(names)
	return Report{len(names), names, s.Managed.Fingerprint}
}

// Load reads only local files, without freshness checks or controller contact.
func Load(dir string) (*vault.Vault, Report, error) {
	data, err := os.ReadFile(filepath.Join(dir, VaultFile))
	if err != nil {
		return nil, Report{}, err
	}
	s, err := decode(data, dir)
	if err != nil {
		return nil, Report{}, err
	}
	return s.Vault, report(s), nil
}

// Verify validates a staged ciphertext without modifying the active snapshot.
func Verify(dir, file string) (Report, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Report{}, err
	}
	s, err := decode(data, dir)
	if err != nil {
		return Report{}, err
	}
	return report(s), nil
}

// Install validates the exact bytes it commits and serializes concurrent installs.
// The old active file remains last-good until the atomic rename. Successful
// installs retain no historical copy that could preserve withdrawn credentials.
func Install(dir, file string) (Report, error) {
	unlock, err := lock(dir)
	if err != nil {
		return Report{}, err
	}
	defer unlock()
	data, err := os.ReadFile(file)
	if err != nil {
		return Report{}, err
	}
	s, err := decode(data, dir)
	if err != nil {
		return Report{}, err
	}
	path := filepath.Join(dir, VaultFile)
	// Compare content as well as the publisher fingerprint: the recipient cannot
	// recompute the publisher's HMAC, so the fingerprint alone isn't a validator.
	oldData, readErr := os.ReadFile(path)
	if readErr == nil {
		old, err := decode(oldData, dir)
		if err == nil {
			before, _ := json.Marshal(old.Vault)
			after, _ := json.Marshal(s.Vault)
			if old.Managed == s.Managed && bytes.Equal(before, after) {
				if err := os.Chmod(path, 0600); err != nil {
					return Report{}, err
				}
				return report(s), nil
			}
		}
	}
	if err := atomicWrite(path, data); err != nil {
		return Report{}, fmt.Errorf("installing snapshot: %w", err)
	}
	return report(s), nil
}
