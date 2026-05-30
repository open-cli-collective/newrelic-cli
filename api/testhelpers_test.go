package api

import (
	"embed"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed testdata/*.json
var testdataFS embed.FS

type RecordedRequest struct {
	Method  string
	Path    string
	Headers http.Header
	Body    []byte
}

type MockServer struct {
	*httptest.Server
	mu         sync.Mutex
	requests   []RecordedRequest
	response   []byte
	statusCode int
	handler    http.HandlerFunc
}

func NewMockServer() *MockServer {
	m := &MockServer{
		statusCode: http.StatusOK,
		response:   []byte(`{}`),
	}

	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requests = append(m.requests, RecordedRequest{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: r.Header.Clone(),
			Body:    body,
		})

		if m.handler != nil {
			m.mu.Unlock()
			m.handler(w, r)
			return
		}

		statusCode := m.statusCode
		response := m.response
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		_, _ = w.Write(response)
	}))

	return m
}

func (m *MockServer) SetResponse(status int, body interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.statusCode = status
	switch v := body.(type) {
	case []byte:
		m.response = v
	case string:
		m.response = []byte(v)
	default:
		data, _ := json.Marshal(body)
		m.response = data
	}
}

func (m *MockServer) SetHandler(h http.HandlerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.handler = h
}

func (m *MockServer) Requests() []RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]RecordedRequest{}, m.requests...)
}

func (m *MockServer) LastRequest() *RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.requests) == 0 {
		return nil
	}
	return &m.requests[len(m.requests)-1]
}

func (m *MockServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *MockServer) AssertRequestCount(t *testing.T, expected int) {
	t.Helper()
	actual := len(m.Requests())
	if actual != expected {
		t.Errorf("expected %d requests, got %d", expected, actual)
	}
}

func (m *MockServer) AssertLastPath(t *testing.T, expected string) {
	t.Helper()
	req := m.LastRequest()
	require.NotNil(t, req, "no requests recorded")
	if req.Path != expected {
		t.Errorf("expected path %q, got %q", expected, req.Path)
	}
}

func (m *MockServer) AssertLastMethod(t *testing.T, expected string) {
	t.Helper()
	req := m.LastRequest()
	require.NotNil(t, req, "no requests recorded")
	if req.Method != expected {
		t.Errorf("expected method %q, got %q", expected, req.Method)
	}
}

func (m *MockServer) AssertLastHeader(t *testing.T, key, expected string) {
	t.Helper()
	req := m.LastRequest()
	require.NotNil(t, req, "no requests recorded")
	actual := req.Headers.Get(key)
	if actual != expected {
		t.Errorf("expected header %q=%q, got %q", key, expected, actual)
	}
}

func NewTestClient(server *MockServer) *Client {
	return &Client{
		APIKey:        "test-api-key",
		AccountID:     "12345",
		Region:        "US",
		BaseURL:       server.URL,
		NerdGraphURL:  server.URL + "/graphql",
		SyntheticsURL: server.URL + "/synthetics",
		HTTPClient:    server.Client(),
	}
}

func LoadTestFixture(t *testing.T, filename string) []byte {
	t.Helper()
	data, err := testdataFS.ReadFile("testdata/" + filename)
	require.NoError(t, err, "failed to load fixture %s", filename)
	return data
}
