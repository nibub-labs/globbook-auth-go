// Package globbookauth implements an OAuth 2.0 client for "Sign in with
// Globbook", the hosted authentication/consent flow exposed by Globbook's
// backend at /api/v2/oauth/*.
//
// It is a dependency-free (standard library only) client SDK intended for
// server-side Go applications that want to let their users sign in with
// their Globbook account. It does not implement an OAuth server, and it
// does not register applications with Globbook — that happens once, ahead
// of time, in Globbook's own developer console, which produces the
// ClientID, ClientSecret, and RedirectURL this package's Config expects.
//
// # Flow
//
// The standard authorization-code flow this package supports has three
// steps:
//
//  1. Redirect the user's browser to [Client.AuthorizationURL]. Globbook
//     shows its own hosted consent screen and, on approval, redirects the
//     browser back to the app's pre-registered RedirectURL with a "code"
//     query parameter.
//  2. Extract that value with [ParseCallbackParams] from the incoming
//     callback request's query parameters, then call
//     [Client.ExchangeCodeForToken] to trade it for an access token.
//  3. Call [Client.GetUserInfo] with the access token to fetch the
//     authenticated user's profile.
//
// # Minimal usage
//
//	client, err := globbookauth.New(globbookauth.Config{
//		ClientID:     os.Getenv("GLOBBOOK_CLIENT_ID"),
//		ClientSecret: os.Getenv("GLOBBOOK_CLIENT_SECRET"),
//		RedirectURL:  "https://yourapp.com/auth/globbook/callback",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Step 1: redirect handler
//	http.Redirect(w, r, client.AuthorizationURL(), http.StatusFound)
//
//	// Step 2 + 3: callback handler
//	code, err := globbookauth.ParseCallbackParams(r.URL.Query())
//	if err != nil {
//		// user denied consent, or Globbook returned an OAuth error
//	}
//	token, err := client.ExchangeCodeForToken(r.Context(), code)
//	user, err := client.GetUserInfo(r.Context(), token.AccessToken)
//
// See the package README and the example/ directory for a complete,
// runnable net/http handler.
package globbookauth
