package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/piekstra/newrelic-cli/internal/config"
)

// Region represents a New Relic region
type Region string

const (
	RegionUS Region = "US"
	RegionEU Region = "EU"
)

// Client is the New Relic API client
type Client struct {
	APIKey        string
	AccountID     string
	Region        string
	BaseURL       string
	NerdGraphURL  string
	SyntheticsURL string
	HTTPClient    *http.Client
}

// ClientConfig holds configuration for creating a new client
type ClientConfig struct {
	APIKey    string
	AccountID string
	Region    string
	Timeout   time.Duration
}

// New creates a new New Relic client using credentials from config/environment
func New() (*Client, error) {
	apiKey, err := config.GetAPIKey()
	if err != nil {
		return nil, err
	}

	accountID, _ := config.GetAccountID() // Optional
	region := config.GetRegion()

	return NewWithConfig(ClientConfig{
		APIKey:    apiKey,
		AccountID: accountID,
		Region:    region,
		Timeout:   30 * time.Second,
	}), nil
}

// NewWithConfig creates a client with explicit configuration
func NewWithConfig(cfg ClientConfig) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}

	c := &Client{
		APIKey:    cfg.APIKey,
		AccountID: cfg.AccountID,
		Region:    cfg.Region,
		HTTPClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}

	// Set URLs based on region
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

	req.Header.Set("Api-Key", c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, &ResponseError{Message: "request failed", Err: err}
	}
	defer resp.Body.Close()

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
		return nil, &GraphQLError{Message: resp.Errors[0].Message}
	}

	return resp.Data, nil
}

// RequireAccountID validates that account ID is configured
func (c *Client) RequireAccountID() error {
	if c.AccountID == "" {
		return ErrAccountIDRequired
	}
	return nil
}

// GetAccountIDInt returns the account ID as an integer
func (c *Client) GetAccountIDInt() (int, error) {
	if err := c.RequireAccountID(); err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(c.AccountID)
	if err != nil {
		return 0, fmt.Errorf("invalid account ID: %s", c.AccountID)
	}
	return id, nil
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
