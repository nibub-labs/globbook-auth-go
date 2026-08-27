package globbookauth

import (
	"errors"
	"net/url"
)

// ErrMissingCallbackCode is returned by [ParseCallbackParams] when "code"
// is not present in the given query values — meaning Globbook's redirect
// back to the app did not include an authorization code, which typically
// means the user denied consent or the request was otherwise rejected
// before reaching that point.
var ErrMissingCallbackCode = errors.New("globbookauth: callback did not include a code parameter")

// CallbackParams is the result of [ParseCallbackParams].
type CallbackParams struct {
	// Code is the authorization code to pass to
	// [Client.ExchangeCodeForToken].
	Code string

	// State is the value Globbook echoed back unchanged, if this app sent
	// one on [Client.AuthorizationURLWithState] (or
	// [Client.AuthorizationURLWithScopesAndState]). Empty if none was sent.
	// If you sent a state value, compare this against the one you stored
	// before redirecting — a mismatch means the callback may be forged
	// (RFC 6749 §10.12) and should be rejected without exchanging the
	// code.
	State string
}

// ParseCallbackParams extracts the authorization code (and, if present,
// the CSRF-protection state value) from the query parameters of the
// callback request Globbook redirects the user's browser to after they
// approve (or deny) the consent screen (step 2 of the flow).
//
// It is framework-agnostic: pass it (*http.Request).URL.Query(), or the
// equivalent url.Values from any net/http-compatible router.
//
// The authorization code is read from the "code" query parameter. If it is
// not present, ParseCallbackParams returns [ErrMissingCallbackCode].
func ParseCallbackParams(values url.Values) (CallbackParams, error) {
	code := values.Get("code")
	if code == "" {
		return CallbackParams{}, ErrMissingCallbackCode
	}
	return CallbackParams{Code: code, State: values.Get("state")}, nil
}
