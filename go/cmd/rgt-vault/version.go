package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/WilliamHudspeth/rgt-vault/go/internal/buildinfo"
)

// versionOutput holds the JSON output for the version subcommand.
type versionOutput struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Dirty   bool   `json:"dirty"`
}

// newVersionCmd creates the version subcommand.
func newVersionCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run: func(cmd *cobra.Command, args []string) {
			jsonFlag, _ := cmd.Flags().GetBool("json")
			if jsonFlag {
				output := versionOutput{
					Version: buildinfo.Version(),
					Commit:  buildinfo.Commit(),
					Date:    buildinfo.Date(),
					Dirty:   buildinfo.Dirty(),
				}
				data, err := json.MarshalIndent(output, "", "  ")
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to marshal version info: %v\n", err)
					os.Exit(1)
				}
				fmt.Println(string(data))
				return
			}
			fmt.Printf("rgt-vault version %s\n", buildinfo.String())
		},
	}
	cmd.Flags().BoolP("json", "j", false, "Output in JSON format")
	return cmd
}
