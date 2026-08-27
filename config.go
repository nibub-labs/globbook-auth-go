package globbookauth

import (
	"errors"
	"fmt"
	"net/http"
)

// DefaultBaseURL is the production Globbook API origin used when
// Config.BaseURL is left empty.
const DefaultBaseURL = "https://globbook.com"

// Config holds the settings required to construct a [Client]. ClientID,
// ClientSecret, and RedirectURL are all required and must correspond to an
// application already registered in Globbook's developer console — this
// package has no application-registration API of its own.
type Config struct {
	// ClientID is the app_id/client_id issued when the application was
	// registered in Globbook's developer console. Required.
	ClientID string

	// ClientSecret is the confidential secret issued alongside ClientID.
	// Required. Never expose this to a browser/client-side context — see
	// the package README's security notes. This value is redacted by
	// String and GoString so it is never accidentally logged.
	ClientSecret string

	// RedirectURL is this application's own callback URL, exactly as
	// registered in Globbook's developer console. Globbook redirects the
	// user's browser back here (with a code query parameter) after they
	// approve the consent screen. Required.
	RedirectURL string

	// BaseURL is the Globbook API origin to talk to, e.g.
	// "https://staging.globbook.com" for a staging environment. Optional;
	// defaults to [DefaultBaseURL] when empty. Must not have a trailing
	// slash requirement — one is stripped automatically if present.
	BaseURL string

	// HTTPClient is the *http.Client used for the token-exchange and
	// userinfo requests. Optional; defaults to http.DefaultClient when
	// nil. Override this to inject timeouts, custom transports, or a
	// mock RoundTripper in tests.
	HTTPClient *http.Client
}

// redactedSecret is the fixed placeholder String/GoString substitute for
// Config.ClientSecret so it never appears in a %v/%+v log line.
const redactedSecret = "[REDACTED]"

// String implements fmt.Stringer, redacting ClientSecret so that logging a
// Config (e.g. via log.Printf("%v", cfg) or %s) never leaks the secret.
func (c Config) String() string {
	return fmt.Sprintf(
		"globbookauth.Config{ClientID:%q, ClientSecret:%q, RedirectURL:%q, BaseURL:%q}",
		c.ClientID, redactedSecret, c.RedirectURL, c.BaseURL,
	)
}

// GoString implements fmt.GoStringer, redacting ClientSecret so that
// logging a Config with %#v never leaks the secret.
func (c Config) GoString() string {
	return fmt.Sprintf(
		"globbookauth.Config{ClientID:%q, ClientSecret:%q, RedirectURL:%q, BaseURL:%q, HTTPClient:%p}",
		c.ClientID, redactedSecret, c.RedirectURL, c.BaseURL, c.HTTPClient,
	)
}

// Validation errors returned by [New]. Use errors.Is to check for a
// specific one, e.g. errors.Is(err, globbookauth.ErrMissingClientID).
var (
	// ErrMissingClientID is returned by New when Config.ClientID is empty.
	ErrMissingClientID = errors.New("globbookauth: ClientID is required")

	// ErrMissingClientSecret is returned by New when Config.ClientSecret
	// is empty.
	ErrMissingClientSecret = errors.New("globbookauth: ClientSecret is required")

	// ErrMissingRedirectURL is returned by New when Config.RedirectURL is
	// empty.
	ErrMissingRedirectURL = errors.New("globbookauth: RedirectURL is required")
)
