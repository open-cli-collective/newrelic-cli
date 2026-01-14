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

// APIKey tests

func TestNewAPIKey(t *testing.T) {
	t.Run("valid NRAK key", func(t *testing.T) {
		key, warning, err := NewAPIKey("NRAK-ABCDEFGHIJ1234567890")

		assert.NoError(t, err)
		assert.Empty(t, warning)
		assert.Equal(t, APIKey("NRAK-ABCDEFGHIJ1234567890"), key)
	})

	t.Run("valid key without NRAK prefix returns warning", func(t *testing.T) {
		key, warning, err := NewAPIKey("ABCDEFGHIJ1234567890WXYZ")

		assert.NoError(t, err)
		assert.NotEmpty(t, warning)
		assert.Contains(t, warning, "NRAK-")
		assert.Equal(t, APIKey("ABCDEFGHIJ1234567890WXYZ"), key)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		_, _, err := NewAPIKey("")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("too short key returns error", func(t *testing.T) {
		_, _, err := NewAPIKey("NRAK-short")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "short")
	})
}

func TestAPIKey_Validate(t *testing.T) {
	t.Run("valid NRAK key", func(t *testing.T) {
		key := APIKey("NRAK-ABCDEFGHIJ1234567890")

		warning, err := key.Validate()

		assert.NoError(t, err)
		assert.Empty(t, warning)
	})

	t.Run("valid key without NRAK prefix returns warning", func(t *testing.T) {
		key := APIKey("ABCDEFGHIJ1234567890WXYZ")

		warning, err := key.Validate()

		assert.NoError(t, err)
		assert.NotEmpty(t, warning)
	})

	t.Run("empty key returns error", func(t *testing.T) {
		key := APIKey("")

		_, err := key.Validate()

		assert.Error(t, err)
	})

	t.Run("too short key returns error", func(t *testing.T) {
		key := APIKey("short")

		_, err := key.Validate()

		assert.Error(t, err)
	})
}

func TestAPIKey_HasNRAKPrefix(t *testing.T) {
	t.Run("has NRAK prefix", func(t *testing.T) {
		key := APIKey("NRAK-ABCDEFGHIJ1234567890")
		assert.True(t, key.HasNRAKPrefix())
	})

	t.Run("no NRAK prefix", func(t *testing.T) {
		key := APIKey("ABCDEFGHIJ1234567890WXYZ")
		assert.False(t, key.HasNRAKPrefix())
	})

	t.Run("lowercase nrak prefix", func(t *testing.T) {
		key := APIKey("nrak-ABCDEFGHIJ1234567890")
		assert.False(t, key.HasNRAKPrefix()) // case-sensitive
	})
}

func TestAPIKey_String(t *testing.T) {
	key := APIKey("NRAK-ABCDEFGHIJ1234567890")
	assert.Equal(t, "NRAK-ABCDEFGHIJ1234567890", key.String())
}

// AccountID tests

func TestNewAccountID(t *testing.T) {
	t.Run("valid numeric account ID", func(t *testing.T) {
		id, err := NewAccountID("12345678")

		assert.NoError(t, err)
		assert.Equal(t, AccountID("12345678"), id)
	})

	t.Run("single digit", func(t *testing.T) {
		id, err := NewAccountID("1")

		assert.NoError(t, err)
		assert.Equal(t, AccountID("1"), id)
	})

	t.Run("large number", func(t *testing.T) {
		id, err := NewAccountID("9999999999")

		assert.NoError(t, err)
		assert.Equal(t, AccountID("9999999999"), id)
	})

	t.Run("empty returns error", func(t *testing.T) {
		_, err := NewAccountID("")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty")
	})

	t.Run("non-numeric returns error", func(t *testing.T) {
		_, err := NewAccountID("abc123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "numeric")
	})

	t.Run("zero returns error", func(t *testing.T) {
		_, err := NewAccountID("0")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "positive")
	})

	t.Run("negative returns error", func(t *testing.T) {
		_, err := NewAccountID("-123")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "positive")
	})
}

func TestAccountID_Int(t *testing.T) {
	t.Run("valid account ID", func(t *testing.T) {
		id := AccountID("12345678")
		assert.Equal(t, 12345678, id.Int())
	})

	t.Run("single digit", func(t *testing.T) {
		id := AccountID("5")
		assert.Equal(t, 5, id.Int())
	})
}

func TestAccountID_Validate(t *testing.T) {
	t.Run("valid account ID", func(t *testing.T) {
		id := AccountID("12345678")
		assert.NoError(t, id.Validate())
	})

	t.Run("empty returns error", func(t *testing.T) {
		id := AccountID("")
		assert.Error(t, id.Validate())
	})

	t.Run("non-numeric returns error", func(t *testing.T) {
		id := AccountID("abc")
		assert.Error(t, id.Validate())
	})

	t.Run("zero returns error", func(t *testing.T) {
		id := AccountID("0")
		assert.Error(t, id.Validate())
	})
}

func TestAccountID_IsEmpty(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		id := AccountID("")
		assert.True(t, id.IsEmpty())
	})

	t.Run("not empty", func(t *testing.T) {
		id := AccountID("12345")
		assert.False(t, id.IsEmpty())
	})
}

func TestAccountID_String(t *testing.T) {
	id := AccountID("12345678")
	assert.Equal(t, "12345678", id.String())
}
