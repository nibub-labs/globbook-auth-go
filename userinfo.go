package globbookauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// UserInfo is the authenticated user's profile, as returned by
// [Client.GetUserInfo]. Its fields mirror the OIDC-style top-level fields
// Globbook's /api/v2/oauth/userinfo endpoint returns.
type UserInfo struct {
	// Subject is the OIDC-style subject identifier: an md5 hash
	// identifying the user, NOT their raw numeric database ID. Stable for
	// a given user, safe to use as a foreign key in your own users table.
	Subject string `json:"sub"`

	// PreferredUsername is the user's @handle/username.
	PreferredUsername string `json:"preferred_username"`

	// ProfileVerified reports whether the user's account is verified.
	ProfileVerified bool `json:"profile_verified"`

	// Email is the user's email address.
	Email string `json:"email"`

	// Name is the user's display name: first and last name joined by a
	// space, or just whichever of the two is non-empty if only one is
	// set.
	Name string `json:"name"`

	// GivenName is the user's first name.
	GivenName string `json:"given_name"`

	// FamilyName is the user's last name.
	FamilyName string `json:"family_name"`

	// Bio is the user's biography text, or "" if unset.
	Bio string `json:"bio"`

	// Picture is a signed CDN URL for the user's avatar, or nil if they
	// have none set. This URL is time-limited (signed) — do not cache it
	// long-term; re-fetch UserInfo when you need a fresh one.
	Picture *string `json:"picture"`

	// CoverImage is a signed CDN URL for the user's cover photo, or nil
	// if they have none set. Like Picture, this URL is time-limited.
	CoverImage *string `json:"cover_image"`

	// Website is the user's website URL, or "" if unset.
	Website string `json:"website"`

	// Birthdate, Gender, PhoneNumber, and Address are restricted claims.
	// Globbook only includes them in the response — the JSON key is
	// omitted entirely otherwise — when BOTH of the following are true:
	//   1. Your app has been verified in the Globbook Developer Console.
	//   2. The user granted the matching scope ("birthdate", "gender",
	//      "phone", "address") on the consent screen during authorization.
	// An unverified app never receives these fields, regardless of which
	// scopes it requests or what the user approves. Check for nil before
	// use — a nil pointer means "not available," not "empty."
	Birthdate *string `json:"birthdate,omitempty"`

	// Gender is the user's gender. See the Birthdate doc comment above for
	// when this field is populated vs. nil.
	Gender *string `json:"gender,omitempty"`

	// PhoneNumber is the user's phone number. See the Birthdate doc
	// comment above for when this field is populated vs. nil.
	PhoneNumber *string `json:"phone_number,omitempty"`

	// Address is city + country, space-joined ("" halves omitted) — this
	// platform stores no street-level address, so this is not a full
	// postal address. See the Birthdate doc comment above for when this
	// field is populated vs. nil.
	Address *string `json:"address,omitempty"`
}

// GetUserInfo fetches the authenticated user's profile (step 3 of the
// flow) by calling GET {baseURL}/api/v2/oauth/userinfo with the given
// access token as a bearer credential.
//
// accessToken is normally the AccessToken field of the [Token] returned
// from [Client.ExchangeCodeForToken].
//
// On a non-2xx response, the returned error wraps a *[AuthError] — use
// errors.As to inspect the OAuth error code, which will be
// [ErrorInvalidToken] if the token is missing, malformed, expired, or
// revoked.
func (c *Client) GetUserInfo(ctx context.Context, accessToken string) (*UserInfo, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: accessToken must not be empty")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v2/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: building request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: performing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: %w", parseAuthError(resp.StatusCode, body))
	}

	var info UserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("globbookauth: GetUserInfo: decoding response body: %w", err)
	}

	return &info, nil
}
