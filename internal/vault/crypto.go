package vault

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// GenerateIdentity creates a new age identity keypair.
func GenerateIdentity(identityPath, pubPath string) error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating identity: %w", err)
	}

	// Write private key with restricted permissions
	if err := os.WriteFile(identityPath, []byte(identity.String()+"\n"), 0600); err != nil {
		return fmt.Errorf("writing identity: %w", err)
	}

	// Write public key
	if err := os.WriteFile(pubPath, []byte(identity.Recipient().String()+"\n"), 0644); err != nil {
		return fmt.Errorf("writing public key: %w", err)
	}

	return nil
}

// LoadRecipient loads the age recipient (public key) from a file.
func LoadRecipient(pubPath string) (age.Recipient, error) {
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("reading public key: %w", err)
	}
	recipient, err := age.ParseX25519Recipient(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, fmt.Errorf("parsing recipient: %w", err)
	}
	return recipient, nil
}

// LoadIdentity loads the age identity (private key) from a file.
func LoadIdentity(identityPath string) (age.Identity, error) {
	data, err := os.ReadFile(identityPath)
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	identity, err := age.ParseX25519Identity(string(bytes.TrimSpace(data)))
	if err != nil {
		return nil, fmt.Errorf("parsing identity: %w", err)
	}
	return identity, nil
}

// Encrypt encrypts data using the public key.
func Encrypt(plaintext []byte, pubPath string) ([]byte, error) {
	recipient, err := LoadRecipient(pubPath)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, fmt.Errorf("creating encrypter: %w", err)
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("closing encrypter: %w", err)
	}

	return buf.Bytes(), nil
}

// Decrypt decrypts data using the identity (private key).
func Decrypt(ciphertext []byte, identityPath string) ([]byte, error) {
	identity, err := LoadIdentity(identityPath)
	if err != nil {
		return nil, err
	}

	r, err := age.Decrypt(bytes.NewReader(ciphertext), identity)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("reading decrypted data: %w", err)
	}

	return plaintext, nil
}
