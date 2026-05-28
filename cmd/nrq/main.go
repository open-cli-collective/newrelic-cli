package main

import (
	"errors"
	"os"

	"github.com/open-cli-collective/newrelic-cli/api"
	"github.com/open-cli-collective/newrelic-cli/internal/exitcode"
)

func main() {
	rootCmd, _ := buildRootCommand()

	if err := rootCmd.Execute(); err != nil {
		// Migration emits its stderr signal synchronously during the
		// migration itself (keychain/migrate.go Phase 3), so a non-zero
		// exit needs no extra flushing.

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
