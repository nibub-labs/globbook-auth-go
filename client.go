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

// Restricted OIDC-style scopes you may pass in
// [AuthorizationURLOptions.Scopes] to request restricted userinfo claims.
// Requesting a scope only has any effect if this app has been verified in
// the Globbook Developer Console — an unverified app's consent screen
// never offers these regardless of what's requested, and GetUserInfo never
// returns them either way unless the user actually grants them at consent
// time.
const (
	ScopeBirthdate = "birthdate"
	ScopeGender    = "gender"
	ScopePhone     = "phone"
	ScopeAddress   = "address"
)

// AuthorizationURLOptions configures [Client.AuthorizationURL].
type AuthorizationURLOptions struct {
	// Scopes are restricted scopes to request in addition to the base
	// profile (see the Scope* constants), rendered as a space-delimited
	// "scope" query parameter. Globbook's consent screen renders each
	// requested scope as a checkbox for the user to approve or deny
	// individually — approving a scope here is not a guarantee it will be
	// granted, and requesting one against an unverified app has no effect
	// at all (see the Restricted claims section of the package README).
	Scopes []string

	// State is an opaque value you generate before redirecting the user
	// here — Globbook echoes it back unchanged in the "state" query
	// parameter on the redirect to your RedirectURL, so
	// [ParseCallbackParams] can hand it back to you to compare against
	// what you stored before the redirect (RFC 6749 §10.12 CSRF
	// protection). Globbook never interprets this value itself. Optional;
	// leave empty to omit it.
	State string
}

// AuthorizationURL builds the URL to redirect the user's browser to in
// order to start the "Sign in with Globbook" flow (step 1). The caller is
// responsible for performing the actual HTTP redirect, e.g.:
//
//	http.Redirect(w, r, client.AuthorizationURL(globbookauth.AuthorizationURLOptions{}), http.StatusFound)
//
// Globbook shows its own hosted consent page at this URL; on approval it
// redirects the browser back to this Client's configured RedirectURL with
// a "code" query parameter appended (see [ParseCallbackParams]).
//
// The RedirectURL itself is not passed as a query parameter here — it is
// resolved server-side by Globbook from the app's pre-registered
// configuration, matching the real backend's /api/v2/oauth/authorize
// contract, which only requires client_id.
//
// Pass a zero-value [AuthorizationURLOptions] to request only the base
// profile with no CSRF-protection state — see the field docs on
// [AuthorizationURLOptions] to request restricted claims and/or set state.
func (c *Client) AuthorizationURL(opts AuthorizationURLOptions) string {
	q := url.Values{}
	q.Set("client_id", c.clientID)
	if len(opts.Scopes) > 0 {
		q.Set("scope", strings.Join(opts.Scopes, " "))
	}
	if opts.State != "" {
		q.Set("state", opts.State)
	}
	return c.baseURL + "/api/v2/oauth/authorize?" + q.Encode()
}
