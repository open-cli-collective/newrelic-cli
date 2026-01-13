// Package exitcode provides standardized exit codes for the CLI.
// These codes allow shell scripts to programmatically handle different error conditions.
package exitcode

// Exit codes for the CLI
const (
	// Success indicates successful execution
	Success = 0

	// GeneralError indicates an unknown or general error
	GeneralError = 1

	// UsageError indicates invalid arguments or flags
	UsageError = 2

	// ConfigError indicates configuration or credential issues
	ConfigError = 3

	// AuthError indicates authentication failed (401/403)
	AuthError = 4

	// APIError indicates an API request failed (4xx)
	APIError = 5

	// ServerError indicates a server error (5xx)
	ServerError = 6
)

// FromHTTPStatus maps HTTP status codes to exit codes
func FromHTTPStatus(status int) int {
	switch {
	case status >= 200 && status < 300:
		return Success
	case status == 401 || status == 403:
		return AuthError
	case status >= 400 && status < 500:
		return APIError
	case status >= 500:
		return ServerError
	default:
		return GeneralError
	}
}
