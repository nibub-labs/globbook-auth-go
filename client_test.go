package globbookauth

import (
	"testing"
)

func validConfig() Config {
	return Config{
		ClientID:     "client-123",
		ClientSecret: "secret-abc",
		RedirectURL:  "https://example.com/callback",
	}
}

func TestNew_ValidatesRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr error
	}{
		{"missing client id", func(c *Config) { c.ClientID = "" }, ErrMissingClientID},
		{"missing client secret", func(c *Config) { c.ClientSecret = "" }, ErrMissingClientSecret},
		{"missing redirect url", func(c *Config) { c.RedirectURL = "" }, ErrMissingRedirectURL},
		{"whitespace client id", func(c *Config) { c.ClientID = "   " }, ErrMissingClientID},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			_, err := New(cfg)
			if err != tt.wantErr {
				t.Fatalf("New() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNew_DefaultsBaseURLAndHTTPClient(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.httpClient == nil {
		t.Error("httpClient should default to a non-nil client")
	}
}

func TestNew_TrimsTrailingSlashFromBaseURL(t *testing.T) {
	cfg := validConfig()
	cfg.BaseURL = "https://staging.globbook.com/"
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	if c.baseURL != "https://staging.globbook.com" {
		t.Errorf("baseURL = %q, want no trailing slash", c.baseURL)
	}
}

func TestAuthorizationURL(t *testing.T) {
	cfg := validConfig()
	cfg.ClientID = "abc 123" // include a char that requires escaping
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{})
	want := DefaultBaseURL + "/api/v2/oauth/authorize?client_id=abc+123"
	if got != want {
		t.Errorf("AuthorizationURL() = %q, want %q", got, want)
	}
}

func TestAuthorizationURL_CustomBaseURL(t *testing.T) {
	cfg := validConfig()
	cfg.BaseURL = "https://staging.globbook.com"
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{})
	want := "https://staging.globbook.com/api/v2/oauth/authorize?client_id=client-123"
	if got != want {
		t.Errorf("AuthorizationURL() = %q, want %q", got, want)
	}
}

func TestAuthorizationURL_WithScopes(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{Scopes: []string{ScopeBirthdate, ScopeGender}})
	want := DefaultBaseURL + "/api/v2/oauth/authorize?client_id=client-123&scope=birthdate+gender"
	if got != want {
		t.Errorf("AuthorizationURL(Scopes) = %q, want %q", got, want)
	}
}

func TestAuthorizationURL_NoScopesMatchesZeroValueOptions(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{Scopes: []string{}})
	want := c.AuthorizationURL(AuthorizationURLOptions{})
	if got != want {
		t.Errorf("AuthorizationURL() with empty scopes = %q, want equal to zero-value options %q", got, want)
	}
}

func TestAuthorizationURL_WithState(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{State: "csrf-token-123"})
	want := DefaultBaseURL + "/api/v2/oauth/authorize?client_id=client-123&state=csrf-token-123"
	if got != want {
		t.Errorf("AuthorizationURL(State) = %q, want %q", got, want)
	}
}

func TestAuthorizationURL_WithScopesAndState(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	got := c.AuthorizationURL(AuthorizationURLOptions{
		Scopes: []string{ScopeBirthdate, ScopeGender},
		State:  "csrf-token-123",
	})
	want := DefaultBaseURL + "/api/v2/oauth/authorize?client_id=client-123&scope=birthdate+gender&state=csrf-token-123"
	if got != want {
		t.Errorf("AuthorizationURL(Scopes, State) = %q, want %q", got, want)
	}
}

func TestConfig_String_RedactsSecret(t *testing.T) {
	cfg := validConfig()
	s := cfg.String()
	if containsSubstring(s, cfg.ClientSecret) {
		t.Errorf("Config.String() leaked the client secret: %s", s)
	}
	if !containsSubstring(s, redactedSecret) {
		t.Errorf("Config.String() should contain the redaction placeholder: %s", s)
	}
}

func TestConfig_GoString_RedactsSecret(t *testing.T) {
	cfg := validConfig()
	s := cfg.GoString()
	if containsSubstring(s, cfg.ClientSecret) {
		t.Errorf("Config.GoString() leaked the client secret: %s", s)
	}
}

func TestClient_String_RedactsSecret(t *testing.T) {
	c, err := New(validConfig())
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}
	s := c.String()
	if containsSubstring(s, "secret-abc") {
		t.Errorf("Client.String() leaked the client secret: %s", s)
	}
}

func containsSubstring(haystack, needle string) bool {
	if needle == "" {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
