package main

import (
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
)

var decryptOutput string

var decryptCmd = &cobra.Command{
	Use:   "decrypt <file.age>",
	Short: "Decrypt an age-encrypted file",
	Long: `Decrypt a file using your Clavis age private key.

Only files encrypted with your public key can be decrypted.
Output goes to stdout by default, or to a file with -o.

Examples:
  clavis decrypt secrets.age                     # output to stdout
  clavis decrypt secrets.age -o secrets.json    # output to file
  clavis decrypt vault.age | jq .               # pipe to jq`,
	Args: cobra.ExactArgs(1),
	RunE: runDecrypt,
}

func init() {
	decryptCmd.Flags().StringVarP(&decryptOutput, "output", "o", "", "Output file (default: stdout)")
	rootCmd.AddCommand(decryptCmd)
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	inputPath := args[0]

	// Check input file exists
	if _, err := os.Stat(inputPath); os.IsNotExist(err) {
		return fmt.Errorf("encrypted file not found: %s", inputPath)
	}

	// Check identity exists
	idPath := config.IdentityPath()
	if _, err := os.Stat(idPath); os.IsNotExist(err) {
		return fmt.Errorf("identity not found at %s\n\nYour private key (identity.txt) is required to decrypt.\nIf you have a backup, copy it to ~/.secrets/identity.txt", idPath)
	}

	// Load identity (private key)
	idFile, err := os.Open(idPath)
	if err != nil {
		return fmt.Errorf("opening identity: %w", err)
	}
	defer idFile.Close()

	identities, err := age.ParseIdentities(idFile)
	if err != nil {
		return fmt.Errorf("parsing identity: %w", err)
	}

	// Open encrypted file
	encFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("opening encrypted file: %w", err)
	}
	defer encFile.Close()

	// Decrypt
	reader, err := age.Decrypt(encFile, identities...)
	if err != nil {
		return fmt.Errorf("decryption failed: %w\n\nThis file may have been encrypted with a different key.", err)
	}

	// Determine output
	var output io.Writer
	if decryptOutput != "" {
		f, err := os.Create(decryptOutput)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer f.Close()
		output = f
	} else {
		output = os.Stdout
	}

	// Write decrypted content
	if _, err := io.Copy(output, reader); err != nil {
		return fmt.Errorf("writing decrypted content: %w", err)
	}

	if decryptOutput != "" {
		fmt.Fprintf(os.Stderr, "Decrypted %s -> %s\n", inputPath, decryptOutput)
	}

	return nil
}
