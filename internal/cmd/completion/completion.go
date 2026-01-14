package completion

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/piekstra/newrelic-cli/internal/cmd/root"
)

// Register adds the completion command to the root command.
func Register(rootCmd *cobra.Command, opts *root.Options) {
	cmd := &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for your shell.

To load completions:

Bash:
  $ source <(newrelic-cli completion bash)

  # To load completions for each session, execute once:
  # Linux:
  $ newrelic-cli completion bash > /etc/bash_completion.d/newrelic-cli

  # macOS:
  $ newrelic-cli completion bash > $(brew --prefix)/etc/bash_completion.d/newrelic-cli

Zsh:
  $ source <(newrelic-cli completion zsh)

  # To load completions for each session, execute once:
  $ newrelic-cli completion zsh > "${fpath[1]}/_newrelic-cli"

  # You may need to start a new shell for completions to take effect.

Fish:
  $ newrelic-cli completion fish | source

  # To load completions for each session, execute once:
  $ newrelic-cli completion fish > ~/.config/fish/completions/newrelic-cli.fish

PowerShell:
  PS> newrelic-cli completion powershell | Out-String | Invoke-Expression

  # To load completions for each session, add to your profile:
  PS> newrelic-cli completion powershell >> $PROFILE`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return rootCmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return rootCmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return rootCmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return rootCmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			}
			return nil
		},
	}
	rootCmd.AddCommand(cmd)
}
