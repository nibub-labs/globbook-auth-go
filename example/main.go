// Command example demonstrates a complete "Sign in with Globbook" flow
// wired into a real net/http server: a "/login" handler that redirects to
// Globbook's consent page, and a "/auth/globbook/callback" handler that
// exchanges the returned code for an access token and fetches the user's
// profile.
//
// This is a demonstration, not a production auth system — it prints the
// resulting profile instead of establishing a session, and it reads
// credentials from environment variables for convenience. A real
// integration would set a session cookie for the resolved user instead of
// just printing their profile.
//
// Run it with:
//
//	GLOBBOOK_CLIENT_ID=your-client-id \
//	GLOBBOOK_CLIENT_SECRET=your-client-secret \
//	GLOBBOOK_REDIRECT_URL=http://localhost:8080/auth/globbook/callback \
//	go run ./example
//
// Then open http://localhost:8080/login in a browser.
package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"

	globbookauth "github.com/nibub-labs/globbook-auth-go"
)

func main() {
	client, err := globbookauth.New(globbookauth.Config{
		ClientID:     os.Getenv("GLOBBOOK_CLIENT_ID"),
		ClientSecret: os.Getenv("GLOBBOOK_CLIENT_SECRET"),
		RedirectURL:  os.Getenv("GLOBBOOK_REDIRECT_URL"),
		// BaseURL: "https://staging.globbook.com", // uncomment to target staging
	})
	if err != nil {
		log.Fatalf("globbookauth.New: %v", err)
	}

	mux := http.NewServeMux()

	// Step 1: send the user to Globbook's hosted consent page.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, client.AuthorizationURL(), http.StatusFound)
	})

	// Step 2 + 3: Globbook redirects back here with ?code=...; exchange
	// it for a token, then fetch the profile.
	mux.HandleFunc("/auth/globbook/callback", func(w http.ResponseWriter, r *http.Request) {
		code, err := globbookauth.ParseCallbackParams(r.URL.Query())
		if err != nil {
			http.Error(w, "sign-in was cancelled or failed: "+err.Error(), http.StatusBadRequest)
			return
		}

		ctx := r.Context()

		token, err := client.ExchangeCodeForToken(ctx, code)
		if err != nil {
			log.Printf("token exchange failed: %v", err)
			http.Error(w, "sign-in failed", http.StatusBadGateway)
			return
		}

		user, err := client.GetUserInfo(ctx, token.AccessToken)
		if err != nil {
			log.Printf("fetching user info failed: %v", err)
			http.Error(w, "sign-in failed", http.StatusBadGateway)
			return
		}

		// A real app would look up or create a local account keyed on
		// user.Subject and establish its own session here. This example
		// just renders the profile it received.
		fmt.Fprintf(w, "<h1>Signed in with Globbook</h1><p>Welcome, %s (@%s)</p><p>%s</p>",
			html.EscapeString(user.Name),
			html.EscapeString(user.PreferredUsername),
			html.EscapeString(user.Email),
		)
	})

	log.Println("listening on http://localhost:8080 — visit /login to start the flow")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
