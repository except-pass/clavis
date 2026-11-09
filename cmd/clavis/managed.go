package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/managed"
	"github.com/except-pass/clavis/internal/vault"
	"github.com/spf13/cobra"
)

func init() {
	command := &cobra.Command{Use: "managed", Short: "Manage this machine's read-only local secrets snapshot"}
	command.AddCommand(&cobra.Command{
		Use: "keygen", Short: "Create or reuse a machine-local identity; print only its public recipient",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient, err := managed.Keygen(config.ManagedDir())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), recipient)
			return nil
		},
	})
	command.AddCommand(&cobra.Command{
		Use: "install <file>", Short: "Verify and atomically install a complete encrypted snapshot",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := managed.Install(config.ManagedDir(), args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		},
	})
	command.AddCommand(&cobra.Command{
		Use: "verify <file>", Short: "Verify a staged snapshot without changing local secrets",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			report, err := managed.Verify(config.ManagedDir(), args[0])
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		},
	})
	rootCmd.AddCommand(command)

	var recipient, namesFile, out string
	export := &cobra.Command{
		Use: "export", Short: "Export only approved named secrets to one machine's public recipient",
		Long: "Export a complete managed snapshot. The caller must authorize names against inventory policy first. Missing or locked names abort the entire export. Outputs only names, count, and a keyed content fingerprint.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Prevent an accidental --out from destroying the source vault or its keys.
			protected := []string{config.VaultPath(), config.IdentityPath(), config.IdentityPubPath(), namesFile}
			protected = append(protected, recipient)
			for _, path := range protected {
				if samePath(out, path) {
					return fmt.Errorf("export output must not overwrite a source file")
				}
			}
			r, err := managed.Recipient(recipient)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(namesFile)
			if err != nil {
				return fmt.Errorf("reading names file: %w", err)
			}
			names := make([]string, 0)
			for _, line := range strings.Split(string(data), "\n") {
				if name := strings.TrimSpace(line); name != "" {
					names = append(names, name)
				}
			}
			source, err := vault.Load(config.VaultPath(), config.IdentityPath())
			if err != nil {
				return fmt.Errorf("loading publisher vault: %w", err)
			}
			report, err := managed.Export(source, config.IdentityPath(), r, names, out)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(report)
		},
	}
	export.Flags().StringVar(&recipient, "recipient", "", "One age X25519 public recipient or a file containing it")
	export.Flags().StringVar(&namesFile, "names-file", "", "Approved secret names, one per line (empty file exports an empty snapshot)")
	export.Flags().StringVar(&out, "out", "", "Encrypted output file (atomically replaced, mode 0600)")
	_ = export.MarkFlagRequired("recipient")
	_ = export.MarkFlagRequired("names-file")
	_ = export.MarkFlagRequired("out")
	rootCmd.AddCommand(export)
}

func samePath(a, b string) bool {
	aa, errA := filepath.Abs(a)
	bb, errB := filepath.Abs(b)
	if errA == nil && errB == nil && aa == bb {
		return true
	}
	ai, errA := os.Stat(a)
	bi, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(ai, bi)
}

// loadReadLayers is used only by read commands. Write commands keep loading
// the user's vault directly and never save the merged view.
func loadReadLayers() (*vault.Vault, map[string]bool, error) {
	user := vault.New()
	userPresent, err := present(config.VaultPath())
	if err != nil {
		return nil, nil, err
	}
	if userPresent {
		user, err = vault.Load(config.VaultPath(), config.IdentityPath())
		if err != nil {
			return nil, nil, err
		}
	}
	machinePresent, err := present(filepath.Join(config.ManagedDir(), managed.VaultFile))
	if err != nil {
		return nil, nil, err
	}
	var machine *vault.Vault
	if machinePresent {
		machine, _, err = managed.Load(config.ManagedDir())
		if err != nil {
			return nil, nil, err
		}
	}
	if !userPresent && !machinePresent {
		return nil, nil, fmt.Errorf("no user or managed vault; run clavis init or install a managed snapshot")
	}
	shadowed := make(map[string]bool)
	if machine != nil {
		for _, s := range machine.Secrets {
			if _, ok := user.Get(s.Name); ok {
				shadowed[s.Name] = true
			} else {
				user.Add(s)
			}
		}
	}
	return user, shadowed, nil
}

func loadReadVault() (*vault.Vault, error) {
	v, _, err := loadReadLayers()
	return v, err
}

// Only an absent vault is optional; a present vault with a missing identity
// remains an error rather than silently changing collision precedence.
func present(path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}
