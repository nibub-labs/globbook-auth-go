package globbookauth

import "fmt"

// AuthError represents an OAuth-standard error returned by Globbook's
// authorization server (the token and userinfo endpoints), as described in
// RFC 6749 section 5.2. It is returned (wrapped) from
// [Client.ExchangeCodeForToken] and [Client.GetUserInfo] whenever Globbook
// responds with a non-2xx status and an OAuth-shaped JSON error body.
//
// Callers that need to branch on the specific OAuth error code (e.g. to
// distinguish an expired/reused code from a misconfigured client) should
// use errors.As:
//
//	var authErr *globbookauth.AuthError
//	if errors.As(err, &authErr) {
//		switch authErr.Code {
//		case globbookauth.ErrorInvalidGrant:
//			// code was invalid, expired, or already used
//		case globbookauth.ErrorInvalidRequest:
//			// a required field was missing
//		}
//	}
type AuthError struct {
	// Code is the machine-readable OAuth error code, e.g. "invalid_grant",
	// "invalid_request", "invalid_token", or "unsupported_media_type".
	Code string

	// Description is the human-readable error_description Globbook
	// returned alongside Code, when present.
	Description string

	// StatusCode is the HTTP status code the response was returned with
	// (e.g. 400 or 401).
	StatusCode int
}

// Error implements the error interface. It returns a message combining the
// OAuth error code and, when present, its description.
func (e *AuthError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Description != "" {
		return fmt.Sprintf("globbookauth: %s (%s)", e.Code, e.Description)
	}
	return fmt.Sprintf("globbookauth: %s", e.Code)
}

// Is enables errors.Is(err, target) to match another *AuthError with the
// same Code, so callers can compare against a sentinel constructed with
// just a Code set (e.g. &AuthError{Code: ErrorInvalidGrant}) without caring
// about Description or StatusCode.
func (e *AuthError) Is(target error) bool {
	t, ok := target.(*AuthError)
	if !ok || t == nil || e == nil {
		return false
	}
	return e.Code == t.Code
}

// Well-known OAuth error codes returned by Globbook's authorization
// server. These are the values that appear in AuthError.Code.
const (
	// ErrorInvalidRequest means a required field (client_id,
	// client_secret, or code) was missing from the token request.
	// Returned with HTTP 400.
	ErrorInvalidRequest = "invalid_request"

	// ErrorInvalidGrant means the client_id/client_secret/code
	// combination was rejected — wrong secret, or an expired/already-used
	// authorization code. Returned with HTTP 401.
	ErrorInvalidGrant = "invalid_grant"

	// ErrorInvalidToken means the access token presented to the userinfo
	// endpoint was missing, malformed, expired, or revoked. Returned with
	// HTTP 401.
	ErrorInvalidToken = "invalid_token"

	// ErrorUnsupportedMediaType means the token request's Content-Type
	// header was not application/x-www-form-urlencoded. Returned with
	// HTTP 415. The SDK itself always sends the correct content type, so
	// this should only appear if something in the request pipeline (e.g.
	// a custom RoundTripper) rewrites it.
	ErrorUnsupportedMediaType = "unsupported_media_type"
)
