package api

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *APIError
		expected string
	}{
		{
			name:     "with body",
			err:      &APIError{StatusCode: 404, Body: "Not Found"},
			expected: "HTTP 404: Not Found",
		},
		{
			name:     "without body",
			err:      &APIError{StatusCode: 500, Message: "Internal Server Error"},
			expected: "HTTP 500: Internal Server Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrNotFound",
			err:      ErrNotFound,
			expected: true,
		},
		{
			name:     "APIError 404",
			err:      &APIError{StatusCode: 404},
			expected: true,
		},
		{
			name:     "APIError 500",
			err:      &APIError{StatusCode: 500},
			expected: false,
		},
		{
			name:     "other error",
			err:      errors.New("some error"),
			expected: false,
		},
		{
			name:     "wrapped ErrNotFound",
			err:      errors.New("wrapped: " + ErrNotFound.Error()),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsNotFound(tt.err))
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "ErrUnauthorized",
			err:      ErrUnauthorized,
			expected: true,
		},
		{
			name:     "APIError 401",
			err:      &APIError{StatusCode: 401},
			expected: true,
		},
		{
			name:     "APIError 403",
			err:      &APIError{StatusCode: 403},
			expected: false,
		},
		{
			name:     "other error",
			err:      errors.New("some error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsUnauthorized(tt.err))
		})
	}
}

func TestGraphQLError_Error(t *testing.T) {
	err := &GraphQLError{Message: "Field 'foo' not found"}
	assert.Equal(t, "GraphQL error: Field 'foo' not found", err.Error())
}

func TestResponseError_Error(t *testing.T) {
	t.Run("with underlying error", func(t *testing.T) {
		err := &ResponseError{
			Message: "failed to parse",
			Err:     errors.New("invalid json"),
		}
		assert.Equal(t, "failed to parse: invalid json", err.Error())
	})

	t.Run("without underlying error", func(t *testing.T) {
		err := &ResponseError{Message: "unexpected response"}
		assert.Equal(t, "unexpected response", err.Error())
	})
}

func TestResponseError_Unwrap(t *testing.T) {
	underlying := errors.New("underlying error")
	err := &ResponseError{Message: "wrapper", Err: underlying}
	assert.Equal(t, underlying, err.Unwrap())
}
