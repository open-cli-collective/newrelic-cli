package api

import (
	"errors"
	"fmt"
)

// Common errors
var (
	ErrAccountIDRequired = errors.New("account ID required - run 'newrelic-cli config set-account-id' or set NEWRELIC_ACCOUNT_ID")
	ErrAPIKeyRequired    = errors.New("API key required - run 'newrelic-cli config set-api-key' or set NEWRELIC_API_KEY")
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

// GraphQLError represents an error from a NerdGraph query
type GraphQLError struct {
	Message string
}

// Error implements the error interface
func (e *GraphQLError) Error() string {
	return fmt.Sprintf("GraphQL error: %s", e.Message)
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
