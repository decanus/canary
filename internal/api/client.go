package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/decanus/canary/internal/consensus"
)

// Client talks to a node's API.
type Client struct {
	Base string // e.g. http://127.0.0.1:18556
	HTTP *http.Client
}

// NewClient returns a client for base.
func NewClient(base string) *Client {
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// Tip fetches GET /tip.
func (c *Client) Tip() (Tip, error) {
	var t Tip
	return t, c.do(http.MethodGet, "/tip", "", &t)
}

// Account fetches GET /account/{addr}.
func (c *Client) Account(addr consensus.Address) (Account, error) {
	var a Account
	return a, c.do(http.MethodGet, "/account/"+hex.EncodeToString(addr[:]), "", &a)
}

// SubmitTx posts a transfer.
func (c *Client) SubmitTx(t *consensus.Transfer) (TxResult, error) {
	var r TxResult
	return r, c.do(http.MethodPost, "/tx", hex.EncodeToString(t.Serialize()), &r)
}

func (c *Client) do(method, path, body string, out any) error {
	req, err := http.NewRequest(method, c.Base+path, strings.NewReader(body))
	if err != nil {
		return err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, e.Error)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
