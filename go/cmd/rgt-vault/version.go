package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo"
)

// versionInfo is the `rgt-vault version --json` document.
type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Dirty   bool   `json:"dirty"`
}

// newVersionCmd builds `rgt-vault version [--json]`. Without --json it prints
// exactly what `rgt-vault --version` prints.
func newVersionCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and build date",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if asJSON {
				return json.NewEncoder(out).Encode(versionInfo{
					Version: buildinfo.Version(),
					Commit:  buildinfo.Commit(),
					Date:    buildinfo.Date(),
					Dirty:   buildinfo.Dirty(),
				})
			}
			_, err := fmt.Fprintf(out, "%s version %s\n", cmd.Root().Name(), buildinfo.String())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the version as a JSON object")
	return cmd
}
