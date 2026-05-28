package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Common errors
var (
	ErrAccountIDRequired = errors.New("account ID required - run 'nrq config set --account-id <id>' or set NEWRELIC_ACCOUNT_ID")
	ErrAPIKeyRequired    = errors.New("API key required - run 'nrq init' or 'nrq set-credential --key api_key --stdin' (NEWRELIC_API_KEY is setup-ingress only)")
	ErrNotFound          = errors.New("resource not found")
	ErrUnauthorized      = errors.New("unauthorized: invalid or missing API key")
)

// APIError represents an HTTP API error
type APIError struct {
	StatusCode int
	Message    string
	Body       string
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Body != "" {
		return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Body)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

// IsNotFound returns true if the error represents a 404
func IsNotFound(err error) bool {
	if errors.Is(err, ErrNotFound) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 404
	}
	return false
}

// IsUnauthorized returns true if the error represents a 401
func IsUnauthorized(err error) bool {
	if errors.Is(err, ErrUnauthorized) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == 401
	}
	return false
}

// GraphQLError represents an error from a NerdGraph query. Message is the
// first error's message (kept for back-compat); Errors carries the full set
// with their `path` / `extensions`, which often hold the actionable detail —
// e.g. which field failed validation on an alert-condition mutation.
type GraphQLError struct {
	Message string
	Errors  []NerdGraphError
}

// Error implements the error interface. It leads with the first message, then
// appends the structured detail NerdGraph returns (each error's path +
// extensions, and any additional errors) so callers see *why* a query was
// rejected instead of a bare "Validation Error".
func (e *GraphQLError) Error() string {
	msg := fmt.Sprintf("GraphQL error: %s", e.Message)
	var details []string
	for _, ge := range e.Errors {
		var parts []string
		if len(e.Errors) > 1 {
			parts = append(parts, ge.Message)
		}
		if len(ge.Path) > 0 {
			parts = append(parts, fmt.Sprintf("path=%v", ge.Path))
		}
		if len(ge.Extensions) > 0 {
			if j, err := json.Marshal(ge.Extensions); err == nil && string(j) != "{}" {
				parts = append(parts, fmt.Sprintf("extensions=%s", j))
			}
		}
		if len(parts) > 0 {
			details = append(details, strings.Join(parts, " "))
		}
	}
	if len(details) > 0 {
		msg += "\n  " + strings.Join(details, "\n  ")
	}
	return msg
}

// ResponseError represents an error parsing the response
type ResponseError struct {
	Message string
	Err     error
}

// Error implements the error interface
func (e *ResponseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap returns the underlying error
func (e *ResponseError) Unwrap() error {
	return e.Err
}
