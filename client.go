package globbookauth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Client is a "Sign in with Globbook" OAuth client. Construct one with
// [New]. A Client is safe for concurrent use by multiple goroutines — it
// holds no mutable state after construction.
type Client struct {
	clientID     string
	clientSecret string
	redirectURL  string
	baseURL      string
	httpClient   *http.Client
}

// New constructs a [Client] from cfg, validating that ClientID,
// ClientSecret, and RedirectURL are all non-empty before returning — it
// fails fast at construction time rather than deferring validation to the
// first API call. cfg.BaseURL defaults to [DefaultBaseURL] when empty, and
// cfg.HTTPClient defaults to http.DefaultClient when nil.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ClientID) == "" {
		return nil, ErrMissingClientID
	}
	if strings.TrimSpace(cfg.ClientSecret) == "" {
		return nil, ErrMissingClientSecret
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, ErrMissingRedirectURL
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		redirectURL:  cfg.RedirectURL,
		baseURL:      baseURL,
		httpClient:   httpClient,
	}, nil
}

// String implements fmt.Stringer, redacting the client secret so that
// logging a Client (e.g. via log.Printf("%v", client) or %s) never leaks
// it.
func (c *Client) String() string {
	if c == nil {
		return "globbookauth.Client(nil)"
	}
	return fmt.Sprintf(
		"globbookauth.Client{ClientID:%q, ClientSecret:%q, RedirectURL:%q, BaseURL:%q}",
		c.clientID, redactedSecret, c.redirectURL, c.baseURL,
	)
}

// GoString implements fmt.GoStringer, redacting the client secret so that
// logging a Client with %#v never leaks it.
func (c *Client) GoString() string {
	return c.String()
}

// AuthorizationURL builds the URL to redirect the user's browser to in
// order to start the "Sign in with Globbook" flow (step 1). The caller is
// responsible for performing the actual HTTP redirect, e.g.:
//
//	http.Redirect(w, r, client.AuthorizationURL(), http.StatusFound)
//
// Globbook shows its own hosted consent page at this URL; on approval it
// redirects the browser back to this Client's configured RedirectURL with
// a "code" query parameter appended (see [ParseCallbackParams]).
//
// The RedirectURL itself is not passed as a query parameter here — it is
// resolved server-side by Globbook from the app's pre-registered
// configuration, matching the real backend's /api/v2/oauth/authorize
// contract, which only requires client_id.
func (c *Client) AuthorizationURL() string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	return c.baseURL + "/api/v2/oauth/authorize?" + q.Encode()
}
