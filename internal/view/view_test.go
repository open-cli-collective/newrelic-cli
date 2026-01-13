package view

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateFormat(t *testing.T) {
	tests := []struct {
		name    string
		format  string
		wantErr bool
	}{
		{"valid table", "table", false},
		{"valid json", "json", false},
		{"valid plain", "plain", false},
		{"invalid format", "xml", true},
		{"empty format", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFormat(tt.format)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestView_Table(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})
	v.NoColor = true

	headers := []string{"ID", "NAME", "STATUS"}
	rows := [][]string{
		{"1", "App One", "healthy"},
		{"2", "App Two", "critical"},
	}

	err := v.Table(headers, rows)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "ID")
	assert.Contains(t, output, "NAME")
	assert.Contains(t, output, "STATUS")
	assert.Contains(t, output, "App One")
	assert.Contains(t, output, "App Two")
	assert.Contains(t, output, "healthy")
	assert.Contains(t, output, "critical")
}

func TestView_Table_Empty(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})

	err := v.Table([]string{"ID"}, [][]string{})
	require.NoError(t, err)
	assert.Empty(t, buf.String())
}

func TestView_JSON(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})

	data := map[string]interface{}{
		"id":     1,
		"name":   "Test",
		"active": true,
	}

	err := v.JSON(data)
	require.NoError(t, err)

	var result map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Equal(t, float64(1), result["id"])
	assert.Equal(t, "Test", result["name"])
	assert.Equal(t, true, result["active"])
}

func TestView_Plain(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})

	rows := [][]string{
		{"1", "App One", "healthy"},
		{"2", "App Two", "critical"},
	}

	err := v.Plain(rows)
	require.NoError(t, err)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 2)
	assert.Equal(t, "1\tApp One\thealthy", lines[0])
	assert.Equal(t, "2\tApp Two\tcritical", lines[1])
}

func TestView_Render_Table(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})
	v.Format = FormatTable
	v.NoColor = true

	headers := []string{"ID", "NAME"}
	rows := [][]string{{"1", "Test"}}
	data := []map[string]interface{}{{"id": 1, "name": "Test"}}

	err := v.Render(headers, rows, data)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "ID")
	assert.Contains(t, buf.String(), "Test")
}

func TestView_Render_JSON(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})
	v.Format = FormatJSON

	headers := []string{"ID", "NAME"}
	rows := [][]string{{"1", "Test"}}
	data := []map[string]interface{}{{"id": 1, "name": "Test"}}

	err := v.Render(headers, rows, data)
	require.NoError(t, err)

	var result []map[string]interface{}
	err = json.Unmarshal(buf.Bytes(), &result)
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestView_Render_Plain(t *testing.T) {
	var buf bytes.Buffer
	v := New(&buf, &bytes.Buffer{})
	v.Format = FormatPlain

	headers := []string{"ID", "NAME"}
	rows := [][]string{{"1", "Test"}}
	data := []map[string]interface{}{{"id": 1, "name": "Test"}}

	err := v.Render(headers, rows, data)
	require.NoError(t, err)
	assert.Equal(t, "1\tTest\n", buf.String())
}

func TestView_Success(t *testing.T) {
	var stdout, stderr bytes.Buffer
	v := New(&stdout, &stderr)
	v.NoColor = true

	v.Success("Operation completed: %s", "success")
	assert.Contains(t, stderr.String(), "Operation completed: success")
}

func TestView_Error(t *testing.T) {
	var stdout, stderr bytes.Buffer
	v := New(&stdout, &stderr)
	v.NoColor = true

	v.Error("Operation failed: %s", "error")
	assert.Contains(t, stderr.String(), "Operation failed: error")
}

func TestView_Warning(t *testing.T) {
	var stdout, stderr bytes.Buffer
	v := New(&stdout, &stderr)
	v.NoColor = true

	v.Warning("Warning: %s", "caution")
	assert.Contains(t, stderr.String(), "Warning: caution")
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		max      int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 8, "hello..."},
		{"very short max", "hello", 3, "hel"},
		{"empty string", "", 10, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Truncate(tt.input, tt.max)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDefault(t *testing.T) {
	v := Default()
	assert.NotNil(t, v)
	assert.NotNil(t, v.Out)
	assert.NotNil(t, v.ErrOut)
	assert.Equal(t, FormatTable, v.Format)
	assert.False(t, v.NoColor)
}
