package fastschema

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
)

const defaultBaseURL = "http://localhost:8000"

// Client calls FastSchema REST API for a single schema (e.g. "event").
// If adminUser and adminPass are set, the client logs in and sends a Bearer token on each request.
type Client struct {
	baseURL  string
	schema   string
	http     *http.Client
	authUser string
	authPass string
	token    string
	tokenMu  sync.RWMutex
}

// NewClient returns a client for the given base URL (e.g. http://localhost:8000) and schema name.
// adminUser and adminPass are optional; when both are set, the client authenticates via /api/auth/local/login and uses the JWT for requests.
func NewClient(baseURL, schema, adminUser, adminPass string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	if schema == "" {
		schema = "event"
	}
	return &Client{
		baseURL:  baseURL,
		schema:   schema,
		http:     &http.Client{},
		authUser: adminUser,
		authPass: adminPass,
	}
}

// Event is a single record (matches FastSchema response and create/update payload).
type Event struct {
	ID          int    `json:"id,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// listResponse wraps list API response (items in data).
type listResponse struct {
	Data struct {
		Items []Event `json:"items"`
	} `json:"data"`
}

// singleResponse wraps create/update API response (single record in data).
type singleResponse struct {
	Data Event `json:"data"`
}

// loginResponse wraps POST /api/auth/local/login response.
type loginResponse struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

func (c *Client) getToken() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

func (c *Client) setToken(t string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = t
}

func (c *Client) clearToken() {
	c.setToken("")
}

// login obtains a JWT from FastSchema and stores it for subsequent requests.
func (c *Client) login() error {
	body, _ := json.Marshal(map[string]string{"login": c.authUser, "password": c.authPass})
	u := c.baseURL + "/api/auth/local/login"
	resp, err := c.http.Post(u, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login: %s: %s", resp.Status, string(b))
	}
	var out loginResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	if out.Data.Token == "" {
		return fmt.Errorf("login: empty token in response")
	}
	c.setToken(out.Data.Token)
	return nil
}

// ensureToken ensures a valid token when auth credentials are configured.
func (c *Client) ensureToken() error {
	if c.authUser == "" || c.authPass == "" {
		return nil
	}
	if c.getToken() != "" {
		return nil
	}
	return c.login()
}

// do runs the request with optional Bearer token and retries once on 401 after re-login.
// Requests with a body must set req.GetBody so the request can be replayed on retry.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	if err := c.ensureToken(); err != nil {
		return nil, err
	}
	if t := c.getToken(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusUnauthorized && c.authUser != "" {
		resp.Body.Close()
		c.clearToken()
		if err := c.login(); err != nil {
			return nil, err
		}
		// Retry with a clone so the body can be re-read when GetBody is set
		req2 := req.Clone(context.Background())
		if t := c.getToken(); t != "" {
			req2.Header.Set("Authorization", "Bearer "+t)
		}
		return c.http.Do(req2)
	}
	return resp, nil
}

func (c *Client) contentPath(id int) string {
	if id == 0 {
		return fmt.Sprintf("%s/api/content/%s", c.baseURL, c.schema)
	}
	return fmt.Sprintf("%s/api/content/%s/%d", c.baseURL, c.schema, id)
}

// List returns all events (paginated; this uses default limit).
// If the content schema does not exist yet (e.g. 400 "model not found"), returns an empty list and nil so the web can show empty state.
func (c *Client) List() ([]Event, error) {
	u, _ := url.Parse(c.contentPath(0))
	u.RawQuery = "limit=100"
	req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// No content/schema yet: treat as empty list and let the web show empty state (401 stays as error)
		if (resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusNotFound) && bytes.Contains(body, []byte("not found")) {
			return []Event{}, nil
		}
		return nil, fmt.Errorf("list: %s: %s", resp.Status, string(body))
	}
	var out listResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Data.Items, nil
}

// Get fetches one event by ID.
func (c *Client) Get(id int) (Event, error) {
	req, _ := http.NewRequest(http.MethodGet, c.contentPath(id), nil)
	resp, err := c.do(req)
	if err != nil {
		return Event{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return Event{}, fmt.Errorf("get: %s: %s", resp.Status, string(body))
	}
	var out singleResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Event{}, err
	}
	return out.Data, nil
}

// Create creates a new event.
func (c *Client) Create(e Event) (Event, error) {
	body, _ := json.Marshal(e)
	req, _ := http.NewRequest(http.MethodPost, c.contentPath(0), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	resp, err := c.do(req)
	if err != nil {
		return Event{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return Event{}, fmt.Errorf("create: %s: %s", resp.Status, string(b))
	}
	var out singleResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Event{}, err
	}
	return out.Data, nil
}

// Update updates an existing event (PUT).
func (c *Client) Update(id int, e Event) (Event, error) {
	body, _ := json.Marshal(e)
	req, _ := http.NewRequest(http.MethodPut, c.contentPath(id), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	resp, err := c.do(req)
	if err != nil {
		return Event{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return Event{}, fmt.Errorf("update: %s: %s", resp.Status, string(b))
	}
	var out singleResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Event{}, err
	}
	return out.Data, nil
}

// Delete deletes an event.
func (c *Client) Delete(id int) error {
	req, _ := http.NewRequest(http.MethodDelete, c.contentPath(id), nil)
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete: %s: %s", resp.Status, string(b))
	}
	return nil
}
