package globbookauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// roundTripFunc adapts a function to http.RoundTripper, for injecting a
// mock transport into Config.HTTPClient without hitting the network.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func newTestClient(t *testing.T, transport roundTripFunc) *Client {
	t.Helper()
	cfg := validConfig()
	cfg.HTTPClient = &http.Client{Transport: transport}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	return c
}

func jsonResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestExchangeCodeForToken_Success(t *testing.T) {
	var capturedReq *http.Request
	var capturedBody []byte

	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		capturedReq = req
		b, _ := io.ReadAll(req.Body)
		capturedBody = b
		return jsonResponse(200, `{"access_token":"tok-xyz","token_type":"Bearer","expires_in":3600}`), nil
	})

	token, err := client.ExchangeCodeForToken(context.Background(), "auth-code-1")
	if err != nil {
		t.Fatalf("ExchangeCodeForToken() unexpected error: %v", err)
	}

	if token.AccessToken != "tok-xyz" {
		t.Errorf("AccessToken = %q, want %q", token.AccessToken, "tok-xyz")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want %d", token.ExpiresIn, 3600)
	}

	// Verify request shape: method, content type, and form body fields.
	if capturedReq.Method != http.MethodPost {
		t.Errorf("Method = %q, want POST", capturedReq.Method)
	}
	if ct := capturedReq.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", ct)
	}
	if capturedReq.URL.String() != DefaultBaseURL+"/api/v2/oauth/token" {
		t.Errorf("URL = %q, want %q", capturedReq.URL.String(), DefaultBaseURL+"/api/v2/oauth/token")
	}

	form, err := url.ParseQuery(string(capturedBody))
	if err != nil {
		t.Fatalf("failed to parse captured body as form: %v", err)
	}
	if form.Get("client_id") != "client-123" {
		t.Errorf("form client_id = %q, want %q", form.Get("client_id"), "client-123")
	}
	if form.Get("client_secret") != "secret-abc" {
		t.Errorf("form client_secret = %q, want %q", form.Get("client_secret"), "secret-abc")
	}
	if form.Get("code") != "auth-code-1" {
		t.Errorf("form code = %q, want %q", form.Get("code"), "auth-code-1")
	}
}

func TestExchangeCodeForToken_InvalidGrant(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return jsonResponse(401, `{"error":"invalid_grant","error_description":"code expired"}`), nil
	})

	_, err := client.ExchangeCodeForToken(context.Background(), "stale-code")
	if err == nil {
		t.Fatal("expected an error, got nil")
	}

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("errors.As failed to find *AuthError in: %v", err)
	}
	if authErr.Code != ErrorInvalidGrant {
		t.Errorf("Code = %q, want %q", authErr.Code, ErrorInvalidGrant)
	}
	if authErr.Description != "code expired" {
		t.Errorf("Description = %q, want %q", authErr.Description, "code expired")
	}
	if authErr.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", authErr.StatusCode)
	}
}

func TestExchangeCodeForToken_InvalidRequest(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return jsonResponse(400, `{"error":"invalid_request","error_description":"missing client_id"}`), nil
	})

	_, err := client.ExchangeCodeForToken(context.Background(), "some-code")

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("errors.As failed to find *AuthError in: %v", err)
	}
	if authErr.Code != ErrorInvalidRequest {
		t.Errorf("Code = %q, want %q", authErr.Code, ErrorInvalidRequest)
	}

	// errors.Is should also match a sentinel AuthError with only Code set.
	if !errors.Is(err, &AuthError{Code: ErrorInvalidRequest}) {
		t.Error("errors.Is did not match a sentinel AuthError with the same Code")
	}
	if errors.Is(err, &AuthError{Code: ErrorInvalidGrant}) {
		t.Error("errors.Is incorrectly matched a sentinel AuthError with a different Code")
	}
}

func TestExchangeCodeForToken_EmptyCode(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called when code is empty")
		return nil, nil
	})

	_, err := client.ExchangeCodeForToken(context.Background(), "   ")
	if err == nil {
		t.Fatal("expected an error for empty code")
	}
}

func TestExchangeCodeForToken_NetworkError(t *testing.T) {
	sentinel := errors.New("connection refused")
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return nil, sentinel
	})

	_, err := client.ExchangeCodeForToken(context.Background(), "some-code")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected wrapped network error to unwrap to sentinel, got: %v", err)
	}
}

func TestGetUserInfo_Success(t *testing.T) {
	var capturedAuthHeader string

	body := `{
		"sub": "md5hash",
		"preferred_username": "janedoe",
		"profile_verified": true,
		"email": "jane@example.com",
		"name": "Jane Doe",
		"given_name": "Jane",
		"family_name": "Doe",
		"bio": "",
		"picture": null,
		"cover_image": null,
		"website": ""
	}`

	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		capturedAuthHeader = req.Header.Get("Authorization")
		return jsonResponse(200, body), nil
	})

	info, err := client.GetUserInfo(context.Background(), "tok-xyz")
	if err != nil {
		t.Fatalf("GetUserInfo() unexpected error: %v", err)
	}

	if capturedAuthHeader != "Bearer tok-xyz" {
		t.Errorf("Authorization header = %q, want %q", capturedAuthHeader, "Bearer tok-xyz")
	}
	if info.Subject != "md5hash" {
		t.Errorf("Subject = %q, want %q", info.Subject, "md5hash")
	}
	if info.Email != "jane@example.com" {
		t.Errorf("Email = %q, want %q", info.Email, "jane@example.com")
	}
	if info.Picture != nil {
		t.Errorf("Picture = %v, want nil", info.Picture)
	}
	if !info.ProfileVerified {
		t.Error("ProfileVerified = false, want true")
	}
	if info.Birthdate != nil {
		t.Errorf("Birthdate = %v, want nil when the key is omitted", *info.Birthdate)
	}
	if info.Gender != nil {
		t.Errorf("Gender = %v, want nil when the key is omitted", *info.Gender)
	}
	if info.PhoneNumber != nil {
		t.Errorf("PhoneNumber = %v, want nil when the key is omitted", *info.PhoneNumber)
	}
	if info.Address != nil {
		t.Errorf("Address = %v, want nil when the key is omitted", *info.Address)
	}
}

func TestGetUserInfo_RestrictedClaimsGranted(t *testing.T) {
	body := `{
		"sub": "md5hash",
		"preferred_username": "janedoe",
		"profile_verified": true,
		"email": "jane@example.com",
		"name": "Jane Doe",
		"given_name": "Jane",
		"family_name": "Doe",
		"bio": "",
		"picture": null,
		"cover_image": null,
		"website": "",
		"birthdate": "1990-01-02",
		"gender": "female",
		"phone_number": "+15551234567",
		"address": "Colombo Sri Lanka"
	}`

	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return jsonResponse(200, body), nil
	})

	info, err := client.GetUserInfo(context.Background(), "tok-xyz")
	if err != nil {
		t.Fatalf("GetUserInfo() unexpected error: %v", err)
	}

	if info.Birthdate == nil || *info.Birthdate != "1990-01-02" {
		t.Errorf("Birthdate = %v, want \"1990-01-02\"", info.Birthdate)
	}
	if info.Gender == nil || *info.Gender != "female" {
		t.Errorf("Gender = %v, want \"female\"", info.Gender)
	}
	if info.PhoneNumber == nil || *info.PhoneNumber != "+15551234567" {
		t.Errorf("PhoneNumber = %v, want \"+15551234567\"", info.PhoneNumber)
	}
	if info.Address == nil || *info.Address != "Colombo Sri Lanka" {
		t.Errorf("Address = %v, want \"Colombo Sri Lanka\"", info.Address)
	}
}

func TestGetUserInfo_InvalidToken(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		return jsonResponse(401, `{"error":"invalid_token","error_description":"token expired"}`), nil
	})

	_, err := client.GetUserInfo(context.Background(), "expired-token")

	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("errors.As failed to find *AuthError in: %v", err)
	}
	if authErr.Code != ErrorInvalidToken {
		t.Errorf("Code = %q, want %q", authErr.Code, ErrorInvalidToken)
	}
}

func TestGetUserInfo_EmptyAccessToken(t *testing.T) {
	client := newTestClient(t, func(req *http.Request) (*http.Response, error) {
		t.Fatal("transport should not be called when accessToken is empty")
		return nil, nil
	})

	_, err := client.GetUserInfo(context.Background(), "")
	if err == nil {
		t.Fatal("expected an error for empty access token")
	}
}

func TestAuthError_ErrorMessage(t *testing.T) {
	withDesc := &AuthError{Code: "invalid_grant", Description: "code expired"}
	if withDesc.Error() == "" {
		t.Error("Error() should not be empty")
	}

	withoutDesc := &AuthError{Code: "invalid_grant"}
	if withoutDesc.Error() == "" {
		t.Error("Error() should not be empty even with no description")
	}
}
