# Upgrading

## Headless mode

This release adds [headless mode](headless.md), a JSON API for the login, account
and two-factor authentication flows, served where you include `hidp.api.urls`. The
changes below can affect a project without it too.

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
- Django OAuth Toolkit 3.4 or later is required. It handles `prompt=create`, which
  it refused with a 400 before: HIdP's own handling no longer ran. A logged-in user
  now continues the authorization instead of seeing the registration page, `next`
  is an absolute URL, discovery lists `create` in `prompt_values_supported`, and the
  `registration_url` attribute of `hidp.oidc_provider.views.AuthorizationView` is
  gone: set `OIDC_RP_INITIATED_REGISTRATION_URL` instead.
- The HTML email verification page keeps its token under its own session key,
  `_email_verification_token`. A user who opened a verification link just before
  the upgrade opens it again.
- The OTP setup page sends a user who must first verify with a recovery code to the
  `otp_verify` URL of `HIDP_FRONTEND_URLS` when it is set.
- The OTP views of the API are only mounted when `django_otp.plugins.otp_totp` and
  `django_otp.plugins.otp_static` are installed too, like the HTML views.
- The rate limit message and the CSRF failure message of the API are translated.
- The OIDC login token is used once: opening the login link of a callback again
  shows `oidc_error=invalid_token`.
- A user links one account per provider. Linking a second one shows a form error.
- An OIDC backend gets the claims of the provider as `claims`, when every OIDC
  backend accepts that argument. Add `claims=None` to the `authenticate` method of
  your subclass of `OIDCModelBackend` (system check `hidp.W002`).

### Code

- `get_verify_email_url` takes the verification token instead of the user.
- The HTML OTP views name their mailers in class attributes: `disabled_mailer`,
  `regenerated_mailer`, `configured_mailer` and `recovery_code_used_mailer`.
- The account views log failed emails to `hidp.accounts.flows` instead of
  `hidp.accounts.views`.

### New settings and checks

- `HIDP_FRONTEND_URLS` and `HIDP_API_USER_SERIALIZER`, see
  [headless mode](headless.md#settings).
- System checks `hidp.E011` to `hidp.E014`, which only apply when
  `hidp.api.urls` is included or `HIDP_API_USER_SERIALIZER` is set.
- `HIDP_API_PATH_PREFIXES`, for APIs that are not Django REST framework, see
  [headless mode](headless.md#apis-that-are-not-django-rest-framework), with
  checks `hidp.E018` and `hidp.W003`.
- System check `hidp.E016` for an unresolvable `OIDC_RP_INITIATED_REGISTRATION_URL`.
- Logging in with an OIDC provider in headless mode: the `login`,
  `oidc_registration`, `oidc_link` and `email_verification_required` keys of
  `HIDP_FRONTEND_URLS`, `hidp.config.headless_urls`, and system checks `hidp.E015`
  and `hidp.E017`. See [headless mode](headless.md#logging-in-with-an-oidc-provider).
- `trust_email_verified_claim` and `is_email_verified` on OIDC clients, see
  [Configure OIDC Clients](configure-oidc-clients.md#verified-email-addresses).
- `MicrosoftOIDCClient` takes a `tenant_id`, for single-tenant applications.
