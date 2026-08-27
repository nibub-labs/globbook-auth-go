# Changelog

All notable changes to this project are documented in this file.

## 1.1.0

**Note on breaking changes below**: this release changes two function signatures. This package has
no known external consumers yet, so the breaking surface is deliberately absorbed into 1.1.0 now,
while the cost of doing so is near zero, rather than carrying it forward indefinitely.

- **Breaking**: `Client.AuthorizationURL()` now takes an `AuthorizationURLOptions` argument
  (`AuthorizationURL(AuthorizationURLOptions{})` for the previous no-args behavior).
  `AuthorizationURLWithScopes(scopes ...string)` has been removed — pass `Scopes` on the same
  options struct instead. This replaces two separate methods with one, so the same struct can also
  carry the new `State` field (see below) without a combinatorial explosion of `WithXxx` variants.
- **Breaking**: `ParseCallbackParams` now returns `(CallbackParams, error)` instead of
  `(string, error)`. Update `code, err := ParseCallbackParams(values)` to
  `params, err := ParseCallbackParams(values)` and use `params.Code`.
- **Fixed**: `UserInfo.Birthdate` and `UserInfo.Gender` are now `*string` instead of `string`.
  Globbook's `/api/v2/oauth/userinfo` omits these fields entirely (not as empty strings) unless
  your app is verified in the Globbook Developer Console and the user granted the matching scope
  at consent time — the previous `string` type couldn't represent "not available" distinctly from
  "empty," and silently decoded a missing key to `""`. If you compared either field to `""`,
  switch to a nil check instead.
- **Added**: `UserInfo.PhoneNumber` and `UserInfo.Address` (`*string`) — restricted claims that
  were previously unreachable through this SDK entirely.
- **Added**: `AuthorizationURLOptions.Scopes` and the `Scope*` constants (`ScopeBirthdate`,
  `ScopeGender`, `ScopePhone`, `ScopeAddress`) to request restricted claims on the authorization
  URL — previously there was no way to request these scopes at all, so `GetUserInfo` could never
  have returned them regardless of app verification status.
- **Added**: `AuthorizationURLOptions.State` / `CallbackParams.State` — optional CSRF protection
  (RFC 6749 §10.12). Generate an unguessable value, pass it as `State`, and compare
  `CallbackParams.State` against it in your callback handler before exchanging the code. Entirely
  opt-in; omitting it changes no other behavior. See the README's "CSRF protection (state)"
  section.

## 1.0.0 - Initial release

Initial release of `globbook-auth-go`, a dependency-free Go client SDK for
"Sign in with Globbook".

- `Client` with `New(Config)` constructor, validating `ClientID`,
  `ClientSecret`, and `RedirectURL` at construction time.
- `Client.AuthorizationURL()` to build the redirect URL for step 1 of the
  OAuth flow (`GET /api/v2/oauth/authorize`).
- `ParseCallbackParams(url.Values)` to extract the authorization code from
  a callback request's `code` query parameter.
- `Client.ExchangeCodeForToken(ctx, code)` implementing the token exchange
  (`POST /api/v2/oauth/token`, `application/x-www-form-urlencoded`),
  returning a `Token`.
- `Client.GetUserInfo(ctx, accessToken)` implementing the userinfo fetch
  (`GET /api/v2/oauth/userinfo`), returning a `UserInfo` with OIDC-style
  top-level fields.
- `AuthError` type carrying the OAuth `error`/`error_description`/HTTP
  status, supporting `errors.As`/`errors.Is`.
- Configurable `BaseURL` (defaults to `https://globbook.com`) and
  injectable `HTTPClient` for staging environments and testing.
- Secret redaction: `Config`/`Client`/`Token` all implement `String`/
  `GoString` so a client secret or access token is never leaked through
  `%v`/`%+v`/`%s` logging.
- Zero third-party runtime dependencies — standard library only.
