package main

import (
	"errors"
	"os"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/exitcode"
	"github.com/open-cli-collective/newrelic-cli/internal/output"
)

func main() {
	rootCmd, _ := buildRootCommand()

	if err := rootCmd.Execute(); err != nil {
		// §1.8/§1.11.6: a one-time migration that succeeded before the
		// command failed must still surface. The success path already
		// spliced it via View.JSON; on a non-zero exit flush any pending
		// block to stdout before mapping the exit code (text-mode emits
		// the stderr line synchronously during migration, so it is
		// already out).
		output.FlushMigrationJSONOnError(os.Stdout)

		// Map error types to exit codes for shell scripting
		var apiErr *api.APIError
		if errors.As(err, &apiErr) {
			os.Exit(exitcode.FromHTTPStatus(apiErr.StatusCode))
		}
		if errors.Is(err, api.ErrAPIKeyRequired) || errors.Is(err, api.ErrAccountIDRequired) {
			os.Exit(exitcode.ConfigError)
		}
		os.Exit(exitcode.GeneralError)
	}
}
