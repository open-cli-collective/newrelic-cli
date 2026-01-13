package client

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// loadTestData loads a JSON fixture file from the testdata directory
func loadTestData(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", filename))
	if err != nil {
		t.Fatalf("failed to load test data %s: %v", filename, err)
	}
	return data
}

// mockServerWithResponse creates a test HTTP server that returns a fixed response
func mockServerWithResponse(t *testing.T, statusCode int, body []byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write(body)
	}))
}

// newTestClient creates a client configured to use test server URLs
func newTestClient(t *testing.T, baseURL, nerdGraphURL, syntheticsURL string) *Client {
	t.Helper()
	return &Client{
		APIKey:        "test-api-key-NRAK-12345",
		AccountID:     "12345",
		Region:        "US",
		BaseURL:       baseURL,
		NerdGraphURL:  nerdGraphURL,
		SyntheticsURL: syntheticsURL,
		HTTPClient:    http.DefaultClient,
	}
}

// newTestClientWithoutAccountID creates a client without an account ID
func newTestClientWithoutAccountID(t *testing.T, baseURL, nerdGraphURL, syntheticsURL string) *Client {
	t.Helper()
	return &Client{
		APIKey:        "test-api-key-NRAK-12345",
		AccountID:     "",
		Region:        "US",
		BaseURL:       baseURL,
		NerdGraphURL:  nerdGraphURL,
		SyntheticsURL: syntheticsURL,
		HTTPClient:    http.DefaultClient,
	}
}
