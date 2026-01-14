package api

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEntityGUID_Parse(t *testing.T) {
	t.Run("valid APM application GUID", func(t *testing.T) {
		// Create a valid GUID: version|domain|type|entityId
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		version, domain, entityType, entityID, err := guid.Parse()

		assert.NoError(t, err)
		assert.Equal(t, "2712640", version)
		assert.Equal(t, "APM", domain)
		assert.Equal(t, "APPLICATION", entityType)
		assert.Equal(t, "137708979", entityID)
	})

	t.Run("invalid base64", func(t *testing.T) {
		guid := EntityGUID("not-valid-base64!!!")

		_, _, _, _, err := guid.Parse()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid GUID format")
	})

	t.Run("invalid format - wrong number of parts", func(t *testing.T) {
		// Only 3 parts instead of 4
		rawGUID := "2712640|APM|APPLICATION"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		_, _, _, _, err := guid.Parse()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected 4 parts")
	})
}

func TestEntityGUID_AppID(t *testing.T) {
	t.Run("valid APM application GUID", func(t *testing.T) {
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		appID, err := guid.AppID()

		assert.NoError(t, err)
		assert.Equal(t, "137708979", appID)
	})

	t.Run("non-APM entity", func(t *testing.T) {
		rawGUID := "2712640|BROWSER|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		_, err := guid.AppID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not for an APM application")
	})

	t.Run("non-APPLICATION type", func(t *testing.T) {
		rawGUID := "2712640|APM|HOST|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		_, err := guid.AppID()

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not for an APM application")
	})
}

func TestEntityGUID_Validate(t *testing.T) {
	t.Run("valid GUID", func(t *testing.T) {
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
		guid := EntityGUID(encoded)

		err := guid.Validate()

		assert.NoError(t, err)
	})

	t.Run("invalid GUID", func(t *testing.T) {
		guid := EntityGUID("invalid")

		err := guid.Validate()

		assert.Error(t, err)
	})
}

func TestEntityGUID_Domain(t *testing.T) {
	rawGUID := "2712640|APM|APPLICATION|137708979"
	encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
	guid := EntityGUID(encoded)

	domain, err := guid.Domain()

	assert.NoError(t, err)
	assert.Equal(t, "APM", domain)
}

func TestEntityGUID_EntityType(t *testing.T) {
	rawGUID := "2712640|APM|APPLICATION|137708979"
	encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
	guid := EntityGUID(encoded)

	entityType, err := guid.EntityType()

	assert.NoError(t, err)
	assert.Equal(t, "APPLICATION", entityType)
}

func TestEntityGUID_EntityID(t *testing.T) {
	rawGUID := "2712640|APM|APPLICATION|137708979"
	encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))
	guid := EntityGUID(encoded)

	entityID, err := guid.EntityID()

	assert.NoError(t, err)
	assert.Equal(t, "137708979", entityID)
}

func TestEntityGUID_String(t *testing.T) {
	guid := EntityGUID("MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=")

	assert.Equal(t, "MXxBUE18QVBQTElDQVRJT058MTIzNDU2Nzg=", guid.String())
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

func TestIsValidEntityGUID(t *testing.T) {
	t.Run("valid base64 GUID", func(t *testing.T) {
		rawGUID := "2712640|APM|APPLICATION|137708979"
		encoded := base64.StdEncoding.EncodeToString([]byte(rawGUID))

		assert.True(t, IsValidEntityGUID(encoded))
	})

	t.Run("short string", func(t *testing.T) {
		assert.False(t, IsValidEntityGUID("short"))
	})

	t.Run("numeric app ID", func(t *testing.T) {
		assert.False(t, IsValidEntityGUID("12345678"))
	})

	t.Run("string with invalid characters", func(t *testing.T) {
		// 50 characters but with invalid character
		assert.False(t, IsValidEntityGUID("abcdefghijklmnopqrstuvwxyz!@#$%^&*()1234567890123"))
	})
}
