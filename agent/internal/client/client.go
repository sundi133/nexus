// Package client talks to the Nexus agent API with device-signed requests.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/votal-ai/nexus/agent/internal/identity"
	"github.com/votal-ai/nexus/agent/internal/release"
)

// Problem is the API's RFC 9457 error body.
type Problem struct {
	Status int    `json:"status"`
	Code   string `json:"code"`
	Title  string `json:"title"`
}

func (p *Problem) Error() string { return fmt.Sprintf("%s (%d %s)", p.Title, p.Status, p.Code) }

// ErrNotEnrolled means the server no longer knows this device (e.g. an admin removed it).
var ErrNotEnrolled = errors.New("device is not enrolled on the server")

type Client struct {
	base     *url.URL
	key      *identity.Key
	deviceID string
	http     *http.Client
	now      func() time.Time
}

// ValidateServer allows https anywhere and plain http only for localhost development.
func ValidateServer(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid server URL %q", raw)
	}
	host := u.Hostname()
	local := host == "localhost" || net.ParseIP(host).IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, fmt.Errorf("server must use https (http is only allowed for localhost): %q", raw)
	}
	return u, nil
}

func New(server string, key *identity.Key, deviceID string) (*Client, error) {
	u, err := ValidateServer(server)
	if err != nil {
		return nil, err
	}
	return &Client{base: u, key: key, deviceID: deviceID, http: &http.Client{Timeout: 30 * time.Second}, now: time.Now}, nil
}

func (c *Client) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	proof, err := c.key.Proof(c.deviceID, http.MethodPost, path, body, c.now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "NexusDevice "+proof)
	req.Header.Set("User-Agent", "nexus-agent")
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		p := &Problem{Status: res.StatusCode}
		if json.Unmarshal(data, p) != nil || p.Title == "" {
			p.Title = strings.TrimSpace(string(data))
		}
		if p.Code == "device_not_enrolled" {
			return fmt.Errorf("%w: %s", ErrNotEnrolled, p.Title)
		}
		return p
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}

type DeviceInfo struct {
	Hostname     string `json:"hostname"`
	Platform     string `json:"platform,omitempty"`
	OSName       string `json:"os_name,omitempty"`
	OSVersion    string `json:"os_version,omitempty"`
	OSBuild      string `json:"os_build,omitempty"`
	Arch         string `json:"arch,omitempty"`
	Model        string `json:"model,omitempty"`
	Serial       string `json:"serial,omitempty"`
	AgentVersion string `json:"agent_version,omitempty"`
}

type EnrollResult struct {
	DeviceID        string `json:"device_id"`
	Organization    string `json:"organization"`
	CheckinInterval int    `json:"checkin_interval_seconds"`
	WebOrigin       string `json:"web_origin"`
}

func (c *Client) Enroll(ctx context.Context, token string, info DeviceInfo) (*EnrollResult, error) {
	var out EnrollResult
	err := c.post(ctx, "/v1/agent/enroll", map[string]any{"token": token, "device": info}, &out)
	return &out, err
}

type CheckinResult struct {
	CheckinInterval   int    `json:"checkin_interval_seconds"`
	InventoryInterval int    `json:"inventory_interval_seconds"`
	Compliance        string `json:"compliance"`
	WebOrigin         string `json:"web_origin"`
	// Update is set when the server's rollout says this device should update.
	Update *release.Offer `json:"update"`
}

func (c *Client) Checkin(ctx context.Context, payload any) (*CheckinResult, error) {
	var out CheckinResult
	err := c.post(ctx, "/v1/agent/checkin", payload, &out)
	return &out, err
}

// Download fetches a release artifact from the Nexus server. Integrity comes
// from the release signature, which the updater checks; this only fetches.
func (c *Client) Download(ctx context.Context, path string, max int64) (io.ReadCloser, error) {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return nil, fmt.Errorf("not a server path: %q", path)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base.String()+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nexus-agent")
	// Downloads can be large and slow; the context bounds them, not the 30s API timeout.
	res, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("download: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > max {
		res.Body.Close()
		return nil, fmt.Errorf("download is %d bytes, expected at most %d", res.ContentLength, max)
	}
	return res.Body, nil
}
