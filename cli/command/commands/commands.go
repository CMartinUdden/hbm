package commands

import (
	"github.com/CMartinUdden/hbm/cli/command/server"
	"github.com/spf13/cobra"
)

// AddCommands adds the commands
func AddCommands(cmd *cobra.Command) {
	cmd.AddCommand(
		server.NewServerCommand(),
	)
}
