package main

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "clavis",
	Short: "Encrypted secrets manager",
	Long: `Clavis manages secrets as tagged key-value bundles, encrypted with age.

Secrets are stored in ~/.secrets/vault.age (encrypted, safe to backup).
Identity key is ~/.secrets/identity.txt (never share).

Quick start:
  clavis list                     # see all secrets
  clavis tags                     # see all tag categories
  clavis list env:prod            # filter by tag
  clavis get prod/db.password     # get single value
  clavis manual                   # full documentation`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("clavis", version)
	},
}

func init() {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			version = v
		}
	}
	rootCmd.AddCommand(versionCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
