// Package managed provides recipient-scoped, locally readable vault snapshots.
package managed

import (
	"fmt"
	"os"
	"path/filepath"

	"filippo.io/age"
	"golang.org/x/sys/unix"
)

const (
	IdentityFile = "identity.txt"
	VaultFile    = "vault.age"
)

// lock serializes key creation and installation. Readers use atomic snapshots
// and need no lock. The lock file stays in place so waiters share one inode.
func lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}

// prepare writes and fsyncs a private temporary file on the destination's
// filesystem. Only complete files are ever renamed into the active path.
func prepare(path string, data []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(path), ".clavis-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(name)
		}
	}()
	// Set exact owner permissions even under an unusually restrictive umask.
	if err = f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err = f.Write(data); err != nil {
		return "", err
	}
	if err = f.Sync(); err != nil {
		return "", err
	}
	if err = f.Close(); err != nil {
		return "", err
	}
	ok = true
	return name, nil
}

func atomicWrite(path string, data []byte) error {
	tmp, err := prepare(path, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func identity(dir string) (*age.X25519Identity, error) {
	data, err := os.ReadFile(filepath.Join(dir, IdentityFile))
	if err != nil {
		return nil, fmt.Errorf("reading managed identity: %w", err)
	}
	id, err := age.ParseX25519Identity(stringTrim(data))
	// Do not include parser errors: malformed inputs may contain private data.
	if err != nil {
		return nil, fmt.Errorf("invalid managed identity")
	}
	return id, nil
}

// Keygen returns the existing public recipient or creates a machine-local key.
// A missing public file is repaired from the private identity, never vice versa.
func Keygen(dir string) (string, error) {
	unlock, err := lock(dir)
	if err != nil {
		return "", err
	}
	defer unlock()
	path := filepath.Join(dir, IdentityFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		// Losing an identity for an installed vault needs explicit operator recovery;
		// generating a replacement here would strand the last-good snapshot.
		if _, err := os.Stat(filepath.Join(dir, VaultFile)); !os.IsNotExist(err) {
			return "", fmt.Errorf("managed vault exists without identity; restore the identity or explicitly remove the vault before rekeying")
		}
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return "", fmt.Errorf("generating managed identity failed")
		}
		if err := atomicWrite(path, []byte(id.String()+"\n")); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	id, err := identity(dir)
	if err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return "", err
	}
	recipient := id.Recipient().String()
	if err := atomicWrite(path+".pub", []byte(recipient+"\n")); err != nil {
		return "", err
	}
	return recipient, nil
}
