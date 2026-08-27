package globbookauth_test

import (
	"fmt"
	"net/url"

	globbookauth "github.com/nibub-labs/globbook-auth-go"
)

// This example shows how to construct a Client and build the URL you
// redirect a user's browser to in order to start the "Sign in with
// Globbook" flow.
func ExampleClient_AuthorizationURL() {
	client, err := globbookauth.New(globbookauth.Config{
		ClientID:     "demo-client-id",
		ClientSecret: "demo-client-secret",
		RedirectURL:  "https://example.com/auth/globbook/callback",
	})
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(client.AuthorizationURL(globbookauth.AuthorizationURLOptions{}))
	// Output: https://globbook.com/api/v2/oauth/authorize?client_id=demo-client-id
}

// This example shows how to extract the authorization code from the query
// parameters of the callback request Globbook redirects the browser to.
func ExampleParseCallbackParams() {
	values := url.Values{}
	values.Set("code", "example-code-value")

	params, err := globbookauth.ParseCallbackParams(values)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Println(params.Code)
	// Output: example-code-value
}
