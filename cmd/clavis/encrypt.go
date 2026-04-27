package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
)

var encryptOutput string

var encryptCmd = &cobra.Command{
	Use:   "encrypt <file>",
	Short: "Encrypt a file with your age identity",
	Long: `Encrypt a file using your Clavis age public key.

The encrypted file can only be decrypted with your identity.txt private key.
Output goes to stdout by default, or to a file with -o.

Examples:
  clavis encrypt secrets.json                    # output to stdout
  clavis encrypt secrets.json -o secrets.age    # output to file
  clavis encrypt secrets.json > secrets.age     # same thing`,
	Args: cobra.ExactArgs(1),
	RunE: runEncrypt,
}

func init() {
	encryptCmd.Flags().StringVarP(&encryptOutput, "output", "o", "", "Output file (default: stdout)")
	rootCmd.AddCommand(encryptCmd)
}

func runEncrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Check input file exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("input file not found: %s", inputPath)
	}

	// Check identity exists
	pubPath := config.IdentityPubPath()
	if _, err := os.Stat(pubPath); os.IsNotExist(err) {
		return fmt.Errorf("identity not found at %s\n\nRun 'clavis init' to create one, or copy your identity.txt to ~/.secrets/", pubPath)
	}

	// Load recipient (public key)
	pubData, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("reading public key: %w", err)
	}

	// Trim whitespace (file may have trailing newline)
	pubKey := string(pubData)
	pubKey = strings.TrimSpace(pubKey)

	recipient, err := age.ParseX25519Recipient(pubKey)
	if err != nil {
		return fmt.Errorf("parsing public key: %w", err)
	}

	// Read input
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	// Determine output
	var output io.Writer
	if encryptOutput != "" {
		f, err := os.Create(encryptOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// Encrypt
	w, err := age.Encrypt(output, recipient)
	if err != nil {
		return fmt.Errorf("initializing encryption: %w", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("finalizing encryption: %w", err)
	}

	if encryptOutput != "" {
		fmt.Fprintf(os.Stderr, "Encrypted %s -> %s\n", inputPath, encryptOutput)
	}

	return nil
}
