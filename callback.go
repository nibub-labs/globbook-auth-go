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

// ParseCallbackParams extracts the authorization code from the query
// parameters of the callback request Globbook redirects the user's browser
// to after they approve (or deny) the consent screen (step 2 of the flow).
//
// It is framework-agnostic: pass it (*http.Request).URL.Query(), or the
// equivalent url.Values from any net/http-compatible router.
//
// The authorization code is read from the "code" query parameter. If it is
// not present, ParseCallbackParams returns [ErrMissingCallbackCode].
func ParseCallbackParams(values url.Values) (string, error) {
	if code := values.Get("code"); code != "" {
		return code, nil
	}
	return "", ErrMissingCallbackCode
}
