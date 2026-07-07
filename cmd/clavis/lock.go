package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/except-pass/clavis/internal/config"
	"github.com/except-pass/clavis/internal/secret"
	"github.com/except-pass/clavis/internal/tags"
	"github.com/except-pass/clavis/internal/vault"
	"golang.org/x/term"
)

var (
	lockPassword string
	lockAll      bool
	lockTag      string
)

var lockCmd = &cobra.Command{
	Use:   "lock [name]",
	Short: "Lock one or more secrets so they cannot be retrieved",
	Long: `Lock secrets individually. A locked secret cannot be read with 'get' or
'show' until it is unlocked. Other secrets stay accessible.

The first lock in a vault sets a shared password; later locks reuse it.

Examples:
  clavis lock prod/mysql          # lock a single secret
  clavis lock --all               # lock every secret
  clavis lock --tag env:prod      # lock every secret with a matching tag

Use 'clavis unlock' to restore access.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runLock,
}

func init() {
	lockCmd.Flags().StringVar(&lockPassword, "password", "", "Lock password (for scripting; prompts if not set)")
	lockCmd.Flags().BoolVar(&lockAll, "all", false, "Lock every secret")
	lockCmd.Flags().StringVar(&lockTag, "tag", "", "Lock every secret matching a tag (category:value)")
	rootCmd.AddCommand(lockCmd)
}

func runLock(cmd *cobra.Command, args []string) error {
	if !exactlyOneSelector(len(args) == 1, lockAll, lockTag != "") {
		return fmt.Errorf("specify a secret name, --all, or --tag")
	}

	v, err := vault.Load(config.VaultPath(), config.IdentityPath())
	if err != nil {
		return fmt.Errorf("loading vault: %w", err)
	}

	targets, err := resolveTargets(v, args, lockAll, lockTag)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		fmt.Println("No matching secrets.")
		return nil
	}

	// Collect the password once. When the vault has no password yet, confirm it.
	password := lockPassword
	if password == "" {
		password, err = promptLockPassword(!v.IsLocked())
		if err != nil {
			return err
		}
	}

	bulk := lockAll || lockTag != ""
	locked := 0
	for _, s := range targets {
		if bulk && s.Locked {
			continue // idempotent for bulk operations
		}
		if err := v.LockSecret(s.Name, password); err != nil {
			return err
		}
		locked++
	}

	if err := v.Save(config.VaultPath(), config.IdentityPubPath()); err != nil {
		return fmt.Errorf("saving vault: %w", err)
	}

	fmt.Printf("Locked %d secret(s).\n", locked)
	return nil
}

// exactlyOneSelector reports whether exactly one target selector was supplied.
func exactlyOneSelector(hasName, all, hasTag bool) bool {
	n := 0
	for _, b := range []bool{hasName, all, hasTag} {
		if b {
			n++
		}
	}
	return n == 1
}

// resolveTargets returns the secrets selected by a name arg, --all, or --tag.
// Exactly one selector is assumed to be set (validated by the caller).
func resolveTargets(v *vault.Vault, args []string, all bool, tag string) ([]*secret.Secret, error) {
	switch {
	case all:
		return v.Secrets, nil
	case tag != "":
		cat, val, err := tags.Parse(tag)
		if err != nil {
			return nil, fmt.Errorf("invalid tag %q: %w", tag, err)
		}
		return v.List(map[string]string{cat: val}), nil
	default:
		s, ok := v.Get(args[0])
		if !ok {
			return nil, fmt.Errorf("secret not found: %s", args[0])
		}
		return []*secret.Secret{s}, nil
	}
}

// promptPassword reads a password from the terminal without echoing.
func promptPassword(label string) (string, error) {
	fmt.Print(label)
	pw, err := term.ReadPassword(0)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

// promptLockPassword prompts for a lock password, confirming it when setNew is
// true (i.e. the vault has no shared password yet).
func promptLockPassword(setNew bool) (string, error) {
	pw, err := promptPassword("Enter lock password: ")
	if err != nil {
		return "", err
	}
	if pw == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	if setNew {
		confirm, err := promptPassword("Confirm password: ")
		if err != nil {
			return "", err
		}
		if pw != confirm {
			return "", fmt.Errorf("passwords do not match")
		}
	}
	return pw, nil
}
