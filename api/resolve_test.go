package api

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseGUID(t *testing.T) {
	t.Run("valid APM application GUID", func(t *testing.T) {
		// Create a valid GUID: accountId|domain|type|entityId
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		accountID, domain, entityType, entityID, err := ParseGUID(encoded)

		assert.NoError(t, err)
		assert.Equal(t, "2712640", accountID)
		assert.Equal(t, "APM", domain)
		assert.Equal(t, "APPLICATION", entityType)
		assert.Equal(t, "137708979", entityID)
	})

	t.Run("invalid base64", func(t *testing.T) {
		_, _, _, _, err := ParseGUID("not-valid-base64!!!")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid GUID format")
	})

	t.Run("invalid format - wrong number of parts", func(t *testing.T) {
		// Only 3 parts instead of 4
		rawGUID := "2712640|APM|APPLICATION"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		_, _, _, _, err := ParseGUID(encoded)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 4 parts")
	})
}

func TestExtractAppIDFromGUID(t *testing.T) {
	t.Run("valid APM application GUID", func(t *testing.T) {
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		appID, err := ExtractAppIDFromGUID(encoded)

		assert.NoError(t, err)
		assert.Equal(t, "137708979", appID)
	})

	t.Run("non-APM entity", func(t *testing.T) {
		rawGUID := "2712640|BROWSER|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		_, err := ExtractAppIDFromGUID(encoded)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not for an APM application")
	})

	t.Run("non-APPLICATION type", func(t *testing.T) {
		rawGUID := "2712640|APM|HOST|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		_, err := ExtractAppIDFromGUID(encoded)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not for an APM application")
	})
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"numeric string", "12345678", true},
		{"zero", "0", true},
		{"single digit", "5", true},
		{"large number", "9999999999999", true},
		{"empty string", "", false},
		{"contains letters", "123abc", false},
		{"contains dash", "123-456", false},
		{"contains space", "123 456", false},
		{"decimal", "123.456", false},
		{"negative", "-123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNumeric(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLooksLikeGUID(t *testing.T) {
	t.Run("valid base64 GUID", func(t *testing.T) {
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		assert.True(t, looksLikeGUID(encoded))
	})

	t.Run("short string", func(t *testing.T) {
		assert.False(t, looksLikeGUID("short"))
	})

	t.Run("numeric app ID", func(t *testing.T) {
		assert.False(t, looksLikeGUID("12345678"))
	})

	t.Run("string with invalid characters", func(t *testing.T) {
		// 50 characters but with invalid character
		assert.False(t, looksLikeGUID("abcdefghijklmnopqrstuvwxyz!@#$%^&*()1234567890123"))
	})
}
