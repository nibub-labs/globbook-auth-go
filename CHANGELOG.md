# Changelog

All notable changes to this project are documented in this file.

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
