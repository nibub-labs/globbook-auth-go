# globbook-auth-go

A dependency-free Go client SDK for **"Sign in with Globbook"** — the
OAuth 2.0-style authorization-code flow exposed by Globbook's backend at
`/api/v2/oauth/*`.

Use this package to let users of your Go server-side application sign in
with their Globbook account. It wraps the three real HTTP calls the flow
requires (authorization redirect, token exchange, userinfo fetch) behind a
small, idiomatic Go API, with zero third-party runtime dependencies —
standard library only.

> **Note**: this package does not register applications with Globbook.
> Before using it you must create an app in Globbook's developer console
> to obtain a `ClientID`, `ClientSecret`, and register your app's
> `RedirectURL` — that is a one-time manual step, unrelated to this SDK.

## Installation

```sh
go get github.com/nibub-labs/globbook-auth-go
```

Requires Go 1.22 or later.

## Quickstart

The full flow has three steps: redirect the user to Globbook, receive the
callback and exchange the code for a token, then fetch the user's profile.
Here's a complete `net/http` example:

```go
package main

import (
	"log"
	"net/http"
	"os"

	globbookauth "github.com/nibub-labs/globbook-auth-go"
)

func main() {
	client, err := globbookauth.New(globbookauth.Config{
		ClientID:     os.Getenv("GLOBBOOK_CLIENT_ID"),
		ClientSecret: os.Getenv("GLOBBOOK_CLIENT_SECRET"),
		RedirectURL:  "https://yourapp.com/auth/globbook/callback",
		// BaseURL is optional; defaults to https://globbook.com.
		// Set it to point at a staging environment instead, e.g.:
		// BaseURL: "https://staging.globbook.com",
	})
	if err != nil {
		log.Fatalf("globbookauth.New: %v", err)
	}

	mux := http.NewServeMux()

	// Step 1: send the user to Globbook's hosted consent page.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, client.AuthorizationURL(), http.StatusFound)
	})

	// Step 2 + 3: Globbook redirects back here with ?code=... after the
	// user approves.
	mux.HandleFunc("/auth/globbook/callback", func(w http.ResponseWriter, r *http.Request) {
		code, err := globbookauth.ParseCallbackParams(r.URL.Query())
		if err != nil {
			http.Error(w, "sign-in was cancelled or failed", http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		token, err := client.ExchangeCodeForToken(ctx, code)
		if err != nil {
			http.Error(w, "sign-in failed", http.StatusBadGateway)
			return
		}

		user, err := client.GetUserInfo(ctx, token.AccessToken)
		if err != nil {
			http.Error(w, "sign-in failed", http.StatusBadGateway)
			return
		}

		// Look up or create a local account keyed on user.Subject, then
		// establish your own session. user.Subject is a stable md5 hash
		// identifying the Globbook user — not their raw numeric ID.
		log.Printf("signed in: %s <%s>", user.Name, user.Email)
	})

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

A runnable version of this example lives in [`example/main.go`](./example/main.go).

## API reference

Full documentation for every exported identifier is available on
[pkg.go.dev](https://pkg.go.dev/github.com/nibub-labs/globbook-auth-go) once
published, and via `go doc` locally (e.g. `go doc ./...` or
`go doc globbookauth.Client`). Summary of the public surface:

### `type Config`

Settings passed to `New`:

| Field          | Required | Description                                                                 |
| -------------- | -------- | ---------------------------------------------------------------------------- |
| `ClientID`     | yes      | App ID from Globbook's developer console.                                    |
| `ClientSecret` | yes      | Confidential secret from Globbook's developer console. Server-side only.    |
| `RedirectURL`  | yes      | Your app's callback URL, exactly as registered with Globbook.               |
| `BaseURL`      | no       | Globbook API origin. Defaults to `https://globbook.com`.                    |
| `HTTPClient`   | no       | `*http.Client` to use for requests. Defaults to `http.DefaultClient`.       |

### `func New(cfg Config) (*Client, error)`

Constructs a `Client`, validating that `ClientID`, `ClientSecret`, and
`RedirectURL` are all non-empty. Returns `ErrMissingClientID`,
`ErrMissingClientSecret`, or `ErrMissingRedirectURL` (checkable with
`errors.Is`) if any is missing — validation happens at construction time,
not deferred to the first API call.

### `func (c *Client) AuthorizationURL() string`

Builds the URL to redirect the user's browser to, to start the sign-in
flow. Does not make an HTTP request itself — your handler is responsible
for issuing the actual redirect (e.g. `http.Redirect`).

### `func ParseCallbackParams(values url.Values) (string, error)`

Extracts the authorization code from a callback request's query
parameters. Framework-agnostic — pass it `(*http.Request).URL.Query()` or
the equivalent from any router. Reads the `code` parameter. Returns
`ErrMissingCallbackCode` if it is not present.

### `func (c *Client) ExchangeCodeForToken(ctx context.Context, code string) (*Token, error)`

Exchanges an authorization code for an access token via
`POST /api/v2/oauth/token` (sent as `application/x-www-form-urlencoded`,
the only content type Globbook's token endpoint accepts). Returns a
`*Token`, or an error wrapping a `*AuthError` on failure.

```go
type Token struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int
}
```

### `func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error)`

Fetches the authenticated user's profile via `GET /api/v2/oauth/userinfo`.
Returns a `*UserInfo`, or an error wrapping a `*AuthError` on failure.

```go
type UserInfo struct {
	Subject           string // OIDC "sub" — an md5 hash, not the numeric user id
	PreferredUsername string
	ProfileVerified   bool
	Email             string
	Name              string
	GivenName         string
	FamilyName        string
	Bio               string
	Picture           *string // signed CDN URL, or nil
	CoverImage        *string // signed CDN URL, or nil
	Website           string
	Birthdate         string // YYYY-MM-DD, or ""
	Gender            string
}
```

## Error handling

Every failed API call (`ExchangeCodeForToken`, `GetUserInfo`) returns an
error wrapping a `*AuthError` when Globbook responds with an OAuth-shaped
error body. Use `errors.As` to inspect it:

```go
token, err := client.ExchangeCodeForToken(ctx, code)
if err != nil {
	var authErr *globbookauth.AuthError
	if errors.As(err, &authErr) {
		switch authErr.Code {
		case globbookauth.ErrorInvalidGrant:
			// code was invalid, expired, or already used — restart the flow
		case globbookauth.ErrorInvalidRequest:
			// a required field was missing — almost certainly a bug in your integration
		default:
			log.Printf("globbook oauth error: %s: %s", authErr.Code, authErr.Description)
		}
		return
	}
	// a non-OAuth error: network failure, context cancellation, etc.
	log.Printf("unexpected error: %v", err)
}
```

`*AuthError` also implements `Is`, so `errors.Is(err, &globbookauth.AuthError{Code: globbookauth.ErrorInvalidGrant})`
works as a shorthand when you only care about matching the `Code`.

Known error codes (all exported as constants): `ErrorInvalidRequest`,
`ErrorInvalidGrant`, `ErrorInvalidToken`, `ErrorUnsupportedMediaType`.

## Security notes

- **`ClientSecret` is a server-side secret.** Never embed it in a mobile
  app, browser bundle, or any client-side code — only call this SDK from
  your backend. Both `Config` and `Client` implement `String`/`GoString`
  to redact the secret from accidental `%v`/`%+v` logging, but that is a
  safety net, not a substitute for keeping it out of client-side code in
  the first place.
- **`Token.AccessToken` is a bearer credential.** Treat it like a
  password: don't log it, don't put it in a URL, transmit it only over
  HTTPS. `Token` also redacts it from `String`/`GoString`.
- Always call this SDK's methods with a `context.Context` that has a
  reasonable deadline in production (e.g. `context.WithTimeout`) so a slow
  or unresponsive Globbook endpoint can't hang your request handler
  indefinitely.

## Testing

The package has no external test dependencies — `go test ./...` runs
entirely offline using a mocked `http.RoundTripper` (via `Config.HTTPClient`)
for the token-exchange and userinfo tests.

```sh
go build ./...
go vet ./...
go test ./...
```

## License

MIT — see [LICENSE](./LICENSE).
