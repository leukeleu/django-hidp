# Upgrading

## Headless mode

This release adds [headless mode](headless.md), a JSON API for the login, account
and two-factor authentication flows. Nothing changes for a project that does not
include `hidp.api.urls`, apart from the changes below.

### Installation

- The `api` extra installs Django REST framework and drf-spectacular, and the
  `oidc_provider` extra now includes it. A project that installs the dependencies
  itself must add `drf-spectacular>=0.28.0` next to `djangorestframework`: the URLs
  of `hidp.api` do not load without it.

### The user endpoint

- `hidp.config.urls` mounts `api/` when `hidp.api` is installed, instead of when
  `hidp.oidc_provider` is installed.
- The router is gone: `api/users/<pk>/`, `UserViewSet` and the URL names
  `api:user-detail` and `api:api-root` are removed, as are format
  suffixes. The user is at `api/users/me/`, named `api:user`.
- An OAuth2 access token needs the `profile` and `email` scopes to read the user,
  and can no longer change it. The tokens of deactivated users are refused.
- The response has `id`, `email` and `has_usable_password` next to the names.

### Behaviour

- The OTP middleware answers Django REST framework views with a 401 JSON response
  instead of a redirect, and redirects to the `otp_verify` and `otp_setup` URLs of
  `HIDP_FRONTEND_URLS` when they are set.
- `RateLimitMiddleware` answers Django REST framework views with a JSON 429.
  `rate_limited_view` is a static method that takes `(request, exception)`.
- Every class-based view counts its requests in a rate limit group of its own.
  Before, views without their own `dispatch` shared some of their limits. The
  counters start again after upgrading.
- The username limit of the HTML login strips and case-folds the username.
- A user with recovery codes but no authenticator app must verify with a recovery
  code before setting up a new app.
- `SetPasswordView` keeps the user logged in after setting a password.
- System check `hidp.E006` also passes when the login endpoint of the API is
  mounted.

### Code

- `get_verify_email_url` takes the verification token instead of the user.
- `EmailChangeCancelView.token_generator` is removed.
- The HTML OTP views name their mailers in class attributes: `disabled_mailer`,
  `regenerated_mailer`, `configured_mailer` and `recovery_code_used_mailer`.
- The account views log failed emails to `hidp.accounts.flows` instead of
  `hidp.accounts.views`.

### New settings and checks

- `HIDP_FRONTEND_URLS` and `HIDP_API_USER_SERIALIZER`, see
  [headless mode](headless.md#settings).
- System checks `hidp.E011` to `hidp.E014`, which only apply when
  `hidp.api.urls` is included or `HIDP_API_USER_SERIALIZER` is set.
