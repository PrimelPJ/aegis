// Package client is a small Go SDK for the Aegis audit log API.
package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to an aegisd server.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a client with a sane default timeout.
func New(baseURL string) *Client {
	return &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

// Event is the payload submitted to the log.
type Event struct {
	Actor    string            `json:"actor"`
	Action   string            `json:"action"`
	Resource string            `json:"resource"`
	Outcome  string            `json:"outcome"`
	Source   string            `json:"source"`
	Meta     map[string]string `json:"meta,omitempty"`
}

// Receipt is returned when an event is accepted.
type Receipt struct {
	Seq      uint64 `json:"seq"`
	Hash     []byte `json:"hash"`
	PrevHash []byte `json:"prev_hash"`
}

// Log submits an event and returns its sealed receipt.
func (c *Client) Log(e Event) (*Receipt, error) {
	body, _ := json.Marshal(e)
	resp, err := c.HTTP.Post(c.BaseURL+"/v1/events", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("log: %s: %s", resp.Status, b)
	}
	var r Receipt
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Checkpoint asks the server to issue a new signed checkpoint.
func (c *Client) Checkpoint() (map[string]any, error) {
	resp, err := c.HTTP.Post(c.BaseURL+"/v1/checkpoint", "application/json", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Verify asks the server to self-audit its persisted log.
func (c *Client) Verify() (map[string]any, error) {
	resp, err := c.HTTP.Get(c.BaseURL + "/v1/verify")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
