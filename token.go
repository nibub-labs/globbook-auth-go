package globbookauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Token is the access token issued by Globbook's token endpoint in
// exchange for a valid authorization code.
type Token struct {
	// AccessToken is the bearer token to present to [Client.GetUserInfo]
	// (and any other Globbook API that accepts a "Sign in with Globbook"
	// bearer token) via an "Authorization: Bearer <AccessToken>" header.
	// Never log this value.
	AccessToken string `json:"access_token"`

	// TokenType is always "Bearer" for tokens issued by Globbook.
	TokenType string `json:"token_type"`

	// ExpiresIn is the number of seconds from the moment this token was
	// issued until it expires. Globbook's token endpoint does not
	// currently issue refresh tokens, so a new authorization-code flow
	// must be started once the token expires.
	ExpiresIn int `json:"expires_in"`
}

// String implements fmt.Stringer, redacting AccessToken so that logging a
// Token (e.g. via log.Printf("%v", token) or %s) never leaks it.
func (t Token) String() string {
	return fmt.Sprintf("globbookauth.Token{AccessToken:%q, TokenType:%q, ExpiresIn:%d}", redactedSecret, t.TokenType, t.ExpiresIn)
}

// GoString implements fmt.GoStringer, redacting AccessToken so that
// logging a Token with %#v never leaks it.
func (t Token) GoString() string {
	return t.String()
}

// oauthErrorBody is the OAuth-standard error JSON shape Globbook returns
// from both the token and userinfo endpoints on failure.
type oauthErrorBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// ExchangeCodeForToken trades the authorization code obtained from
// [ParseCallbackParams] (step 2) for an access token (step 3), by calling
// POST {baseURL}/api/v2/oauth/token.
//
// The request body is sent as application/x-www-form-urlencoded — the
// only content type Globbook's token endpoint accepts; any other content
// type is rejected with a 415 [ErrorUnsupportedMediaType] error, which is
// why this method builds the request itself rather than accepting a
// pre-built *http.Request.
//
// On a non-2xx response, the returned error wraps a *[AuthError] — use
// errors.As to inspect the OAuth error code (e.g. [ErrorInvalidGrant] for
// an expired or already-used code, [ErrorInvalidRequest] for a malformed
// request).
func (c *Client) ExchangeCodeForToken(ctx context.Context, code string) (*Token, error) {
	if strings.TrimSpace(code) == "" {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: code must not be empty")
	}

	form := url.Values{}
	form.Set("client_id", c.clientID)
	form.Set("client_secret", c.clientSecret)
	form.Set("code", code)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: performing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: %w", parseAuthError(resp.StatusCode, body))
	}

	var token Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, fmt.Errorf("globbookauth: ExchangeCodeForToken: decoding response body: %w", err)
	}

	return &token, nil
}

// parseAuthError decodes an OAuth-standard error JSON body into an
// *AuthError carrying the given HTTP status code. If the body cannot be
// parsed as the expected shape (e.g. an upstream proxy returned HTML), it
// falls back to a best-effort AuthError so callers still get a consistent
// *AuthError type rather than a raw decoding error.
func parseAuthError(statusCode int, body []byte) *AuthError {
	var parsed oauthErrorBody
	if err := json.Unmarshal(body, &parsed); err != nil || parsed.Error == "" {
		return &AuthError{
			Code:        "unknown_error",
			Description: strings.TrimSpace(string(body)),
			StatusCode:  statusCode,
		}
	}
	return &AuthError{
		Code:        parsed.Error,
		Description: parsed.ErrorDescription,
		StatusCode:  statusCode,
	}
}
