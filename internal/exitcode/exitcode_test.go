package exitcode

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFromHTTPStatus(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		expected int
	}{
		// Success codes
		{"200 OK", 200, Success},
		{"201 Created", 201, Success},
		{"204 No Content", 204, Success},
		{"299 edge case", 299, Success},

		// Auth errors
		{"401 Unauthorized", 401, AuthError},
		{"403 Forbidden", 403, AuthError},

		// API errors (other 4xx)
		{"400 Bad Request", 400, APIError},
		{"404 Not Found", 404, APIError},
		{"422 Unprocessable", 422, APIError},
		{"429 Rate Limited", 429, APIError},

		// Server errors
		{"500 Internal Server Error", 500, ServerError},
		{"502 Bad Gateway", 502, ServerError},
		{"503 Service Unavailable", 503, ServerError},
		{"504 Gateway Timeout", 504, ServerError},

		// Edge cases
		{"0 unknown", 0, GeneralError},
		{"100 informational", 100, GeneralError},
		{"300 redirect", 300, GeneralError},
		{"600 still server range", 600, ServerError}, // >= 500 is ServerError
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FromHTTPStatus(tt.status)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExitCodeValues(t *testing.T) {
	// Verify exit code values match expected standards
	assert.Equal(t, 0, Success)
	assert.Equal(t, 1, GeneralError)
	assert.Equal(t, 2, UsageError)
	assert.Equal(t, 3, ConfigError)
	assert.Equal(t, 4, AuthError)
	assert.Equal(t, 5, APIError)
	assert.Equal(t, 6, ServerError)
}
