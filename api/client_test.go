package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewWithConfig(t *testing.T) {
	t.Run("US region", func(t *testing.T) {
		cfg := ClientConfig{
			APIKey:    "test-key",
			AccountID: "12345",
			Region:    "US",
		}
		client := NewWithConfig(cfg)

		assert.Equal(t, "test-key", client.APIKey)
		assert.Equal(t, "12345", client.AccountID)
		assert.Equal(t, "US", client.Region)
		assert.Equal(t, "https://api.newrelic.com/v2", client.BaseURL)
		assert.Equal(t, "https://api.newrelic.com/graphql", client.NerdGraphURL)
		assert.Equal(t, "https://synthetics.newrelic.com/synthetics/api/v3", client.SyntheticsURL)
	})

	t.Run("EU region", func(t *testing.T) {
		cfg := ClientConfig{
			APIKey:    "test-key",
			AccountID: "12345",
			Region:    "EU",
		}
		client := NewWithConfig(cfg)

		assert.Equal(t, "https://api.eu.newrelic.com/v2", client.BaseURL)
		assert.Equal(t, "https://api.eu.newrelic.com/graphql", client.NerdGraphURL)
		assert.Equal(t, "https://synthetics.eu.newrelic.com/synthetics/api/v3", client.SyntheticsURL)
	})
}

func TestClient_RequireAccountID(t *testing.T) {
	t.Run("with account ID", func(t *testing.T) {
		client := &Client{AccountID: "12345"}
		assert.NoError(t, client.RequireAccountID())
	})

	t.Run("without account ID", func(t *testing.T) {
		client := &Client{}
		err := client.RequireAccountID()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountIDRequired)
	})
}

func TestClient_GetAccountIDInt(t *testing.T) {
	t.Run("valid account ID", func(t *testing.T) {
		client := &Client{AccountID: "12345"}
		id, err := client.GetAccountIDInt()
		assert.NoError(t, err)
		assert.Equal(t, 12345, id)
	})

	t.Run("invalid account ID", func(t *testing.T) {
		client := &Client{AccountID: "not-a-number"}
		_, err := client.GetAccountIDInt()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid account ID")
	})

	t.Run("empty account ID", func(t *testing.T) {
		client := &Client{}
		_, err := client.GetAccountIDInt()
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrAccountIDRequired)
	})
}

func TestSafeString(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected string
	}{
		{"string value", "hello", "hello"},
		{"nil value", nil, ""},
		{"number value", 123, ""},
		{"bool value", true, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSafeInt(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
	}{
		{"float64 value", float64(42), 42},
		{"nil value", nil, 0},
		{"string value", "123", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := safeInt(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSafeMap(t *testing.T) {
	t.Run("valid map", func(t *testing.T) {
		input := map[string]interface{}{"key": "value"}
		result, ok := safeMap(input)
		assert.True(t, ok)
		assert.Equal(t, input, result)
	})

	t.Run("nil value", func(t *testing.T) {
		_, ok := safeMap(nil)
		assert.False(t, ok)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, ok := safeMap("not a map")
		assert.False(t, ok)
	})
}

func TestSafeSlice(t *testing.T) {
	t.Run("valid slice", func(t *testing.T) {
		input := []interface{}{"a", "b", "c"}
		result, ok := safeSlice(input)
		assert.True(t, ok)
		assert.Equal(t, input, result)
	})

	t.Run("nil value", func(t *testing.T) {
		_, ok := safeSlice(nil)
		assert.False(t, ok)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, ok := safeSlice("not a slice")
		assert.False(t, ok)
	})
}
