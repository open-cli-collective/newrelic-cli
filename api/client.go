package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// ErrNewRemoved is returned by the deprecated New shim. It exists so an
// external importer of this pre-1.0 package gets an actionable runtime
// error instead of a bare compile break, and so the credential-resolution
// move is self-documenting at the old call site.
var ErrNewRemoved = errors.New(
	"api.New() has been removed: the API key now resolves from the OS keyring " +
		"via `nrq init` / `nrq set-credential`, not from this package. " +
		"Construct the client with api.NewWithConfig(api.ClientConfig{...}) " +
		"using values you resolve yourself")

// New is deprecated and non-functional.
//
// Deprecated: New previously resolved credentials from the environment and
// config file. Per Secret-Handling Standard §2.5/§1.11 the api/ package no
// longer reads the keyring, environment, or config, nor runs the §1.8
// migration (that is a command-layer side effect — see NewWithConfig). This
// shim only returns ErrNewRemoved so existing importers fail clearly. Use
// NewWithConfig.
func New() (*Client, error) { return nil, ErrNewRemoved }

// Region represents a New Relic region
type Region string

const (
	RegionUS Region = "US"
	RegionEU Region = "EU"
)

// Client is the New Relic API client.
//
// NerdGraphURL is the supported API endpoint. BaseURL (REST v2) and
// SyntheticsURL (Synthetics REST v3) back only the Deprecated *REST methods:
// New Relic is replacing REST v2 with NerdGraph
// (https://docs.newrelic.com/docs/apis/intro-apis/introduction-new-relic-apis/)
// and has deprecated the Synthetics REST API
// (https://docs.newrelic.com/docs/synthetics/synthetic-monitoring/administration/synthetics-api/).
type Client struct {
	APIKey        APIKey
	AccountID     AccountID
	Region        string
	BaseURL       string
	NerdGraphURL  string
	SyntheticsURL string
	HTTPClient    *http.Client
	Verbose       bool
	Stderr        io.Writer
}

// ClientConfig holds configuration for creating a new client
type ClientConfig struct {
	APIKey    string
	AccountID string
	Region    string
	Timeout   time.Duration
	Verbose   bool
	Stderr    io.Writer
}

// NewWithConfig creates a client with explicit configuration.
//
// This is the SOLE constructor. The former credential-resolving New() was
// removed per §2.5 / §1.11: the api/ package must not read the keyring,
// environment, or config file, nor run the §1.8 migration — those are CLI
// side-effects and would couple the public library to the command layer
// (import cycle). The command layer's lazy resolver
// (root.Options.APIClient) opens the keyring, runs the one-time migration,
// resolves account_id/region (env > config), and passes them here.
func NewWithConfig(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	c := &Client{
		APIKey:    APIKey(cfg.APIKey),
		AccountID: AccountID(cfg.AccountID),
		Region:    cfg.Region,
		HTTPClient: &http.Client{
			Timeout: cfg.Timeout,
		},
		Verbose: cfg.Verbose,
		Stderr:  cfg.Stderr,
	}

	if cfg.Region == "EU" {
		c.BaseURL = "https://api.eu.newrelic.com/v2"
		c.NerdGraphURL = "https://api.eu.newrelic.com/graphql"
		c.SyntheticsURL = "https://synthetics.eu.newrelic.com/synthetics/api/v3"
	} else {
		c.BaseURL = "https://api.newrelic.com/v2"
		c.NerdGraphURL = "https://api.newrelic.com/graphql"
		c.SyntheticsURL = "https://synthetics.newrelic.com/synthetics/api/v3"
	}

	return c
}

// doRequest performs an HTTP request with authentication
func (c *Client) doRequest(method, url string, body interface{}) ([]byte, error) {
	start := time.Now()

	if c.Verbose && c.Stderr != nil {
		fmt.Fprintf(c.Stderr, "[DEBUG] %s %s\n", method, url)
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, &ResponseError{Message: "failed to marshal request body", Err: err}
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, &ResponseError{Message: "failed to create request", Err: err}
	}

	req.Header.Set("Api-Key", c.APIKey.String())
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		if c.Verbose && c.Stderr != nil {
			fmt.Fprintf(c.Stderr, "[DEBUG] Request failed: %v (%s)\n", err, time.Since(start))
		}
		return nil, &ResponseError{Message: "request failed", Err: err}
	}
	defer resp.Body.Close()

	if c.Verbose && c.Stderr != nil {
		fmt.Fprintf(c.Stderr, "[DEBUG] %d %s (%s)\n", resp.StatusCode, resp.Status, time.Since(start))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &ResponseError{Message: "failed to read response", Err: err}
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// NerdGraphQuery executes a GraphQL query against NerdGraph
func (c *Client) NerdGraphQuery(query string, variables map[string]interface{}) (map[string]interface{}, error) {
	reqBody := NerdGraphRequest{
		Query:     query,
		Variables: variables,
	}

	data, err := c.doRequest("POST", c.NerdGraphURL, reqBody)
	if err != nil {
		return nil, err
	}

	var resp NerdGraphResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, &ResponseError{Message: "failed to parse response", Err: err}
	}

	if len(resp.Errors) > 0 {
		return nil, &GraphQLError{Message: resp.Errors[0].Message, Errors: resp.Errors}
	}

	return resp.Data, nil
}

// RequireAccountID validates that account ID is configured
func (c *Client) RequireAccountID() error {
	if c.AccountID.IsEmpty() {
		return ErrAccountIDRequired
	}
	return nil
}

// GetAccountIDInt returns the account ID as an integer
func (c *Client) GetAccountIDInt() (int, error) {
	if err := c.RequireAccountID(); err != nil {
		return 0, err
	}
	if err := c.AccountID.Validate(); err != nil {
		return 0, fmt.Errorf("invalid account ID: %s", c.AccountID)
	}
	return c.AccountID.Int(), nil
}

// safeString safely converts an interface{} to string
func safeString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// safeInt safely converts an interface{} to int
func safeInt(v interface{}) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

// safeIDInt converts a GraphQL ID value to int. GraphQL serializes the ID
// scalar as a JSON string, but some New Relic surfaces emit numbers, so both
// are accepted.
func safeIDInt(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case string:
		n, err := strconv.Atoi(val)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}

// safeInt64 safely converts an interface{} to int64
func safeInt64(v interface{}) int64 {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return 0
}

// safeMap safely converts an interface{} to map[string]interface{}
func safeMap(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

// safeSlice safely converts an interface{} to []interface{}
func safeSlice(v interface{}) ([]interface{}, bool) {
	s, ok := v.([]interface{})
	return s, ok
}
