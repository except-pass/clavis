package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/vault"
)

var editCmd = &cobra.Command{
	Use:   "edit <name>",
	Short: "Edit a secret's values in $EDITOR",
	Args:  cobra.ExactArgs(1),
	RunE:  runEdit,
}

func init() {
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	name := args[0]

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	s, ok := v.Get(name)
	if !ok {
		return fmt.Errorf("secret not found: %s", name)
	}

	// Create temp file with current values
	tmpFile, err := os.CreateTemp("", "clavis-edit-*.txt")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// Write current values
	for k, val := range s.Values {
		fmt.Fprintf(tmpFile, "%s=%s\n", k, val)
	}
	tmpFile.Close()

	// Open in editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = "vi"
	}

	editorCmd := exec.Command(editor, tmpPath)
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

	if err := editorCmd.Run(); err != nil {
		return fmt.Errorf("editor exited with error: %w", err)
	}

	// Read back edited values
	editedFile, err := os.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("reading edited file: %w", err)
	}
	defer editedFile.Close()

	// Clear old values and set new ones
	for k := range s.Values {
		delete(s.Values, k)
	}

	scanner := bufio.NewScanner(editedFile)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			s.Set(parts[0], parts[1])
		}
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Updated secret: %s\n", name)
	return nil
}
