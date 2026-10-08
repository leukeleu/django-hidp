# Headless mode

The `api` extra adds a JSON API for the flows of the HTML views: login,
registration, email verification, password recovery, account management,
two-factor authentication, and logging in with an OIDC provider. A single-page app
or a server-rendered frontend (such as Nuxt or Next.js) can then own the whole user
interface, while HIdP keeps owning the rules: rate limits, anti-enumeration, emails
and OTP policies.

The API shares the session with the HTML views, so a project can offer both, or
only the API.

## Installation

```shell
pip install django-hidp[api]
```

The extra installs Django REST framework and drf-spectacular. Both are required:
the views describe themselves for the OpenAPI schema.

```python
INSTALLED_APPS = [
    ...,
    "rest_framework",
    "hidp.api",
]
```

The API is only served where you include it, under any prefix:

```python
urlpatterns = [
    ...,
    path("api/auth/", include("hidp.api.urls")),
]
```

Its URL names are in the `hidp_api` namespace. `hidp.config.urls` does not mount
it: with `hidp.api` installed, it only mounts `api/users/me/` for
[OAuth2 clients](configure-as-oidc-provider.md). The OTP endpoints are added when
`hidp.otp` is installed.

## The authentication state

`GET session/` returns the authentication state at any time. Login, logout,
signup and the OTP setup and verification endpoints respond with it too:

```json
{
  "user": {
    "id": "0192f1b4-5a4e-7c1e-9b2a-7f3d2c1e0a9b",
    "first_name": "Walter",
    "last_name": "White",
    "email": "walter@example.com",
    "has_usable_password": true
  },
  "pending": []
}
```

- **200**: the user is fully authenticated, and `pending` is empty.
- **401**: the session is anonymous (`user` is `null`, `pending` is empty) or partly
  authenticated. `user` stays `null` until every pending step is done.

A pending step tells the client which screen to show next:

| Step | Meaning | Completed by |
| --- | --- | --- |
| `email_verify` | A verification email was sent. | The link in the email, then logging in again. |
| `otp_setup` | The OTP policy requires two-factor authentication, and the user has no device. | `POST otp/setup/` |
| `otp_verify` | The user must enter a code from their authenticator app. | `POST otp/verify/` or `POST otp/verify/recovery-code/` |

While an OTP step is pending, the OTP middleware answers protected API views,
including your own Django REST framework views, with the same 401 state instead of
a redirect. It only checks users logged in with a session: a request authenticated
by a token or by Basic authentication is not checked for OTP.

## Sessions and CSRF

The API uses [Django sessions](https://docs.djangoproject.com/en/stable/topics/http/sessions/).
The client must send the session cookie with every request, so the frontend is best
served from the same site as the API.

Every unsafe request (POST, PATCH, PUT, DELETE) needs a
[CSRF token](https://docs.djangoproject.com/en/stable/ref/csrf/), anonymous requests
included. `GET session/` sets the `csrftoken` cookie; send its value in the
`X-CSRFToken` header. Django rotates the token when a user logs in, so read the
cookie again after logging in.

A failed CSRF check is a 403 with a JSON `detail`, like every other API error.

A frontend on another origin, such as `app.example.com` next to `api.example.com`,
also needs:

- its exact origin in `CSRF_TRUSTED_ORIGINS`, since Django checks the `Origin` of
  HTTPS requests. Do not use a wildcard such as `https://*.example.com`: any
  subdomain that is taken over can then make requests as the user.
- `CSRF_COOKIE_DOMAIN` set to the shared parent domain, so the frontend can read the
  cookie. Keep `CSRF_COOKIE_HTTPONLY` off.
- `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` on, with the default
  `SameSite=Lax`.
- If you use CORS, list the exact origins and never combine
  `CORS_ALLOW_ALL_ORIGINS` or a broad regex with `CORS_ALLOW_CREDENTIALS`. CSRF
  protection does not cover reads, so any allowed origin can read responses such as
  the OTP secret and recovery codes.

Every response of the API is sent with `Cache-Control: no-store`, since many carry
personal data or secrets.

HIdP's [Content Security Policy](content-security-policy.md) only covers its HTML
views. In headless mode your frontend serves the pages, so it sets its own policy.

## Flows

### Login

`POST login/` with `{username, password}`. A user whose email address is not
verified is not logged in: they are sent a verification email, any other user logged
in on the session is logged out, and the response has a pending `email_verify` step.
Otherwise the response is the authentication state, which may have a pending OTP
step.

Logins are limited by IP address, and to 10 per minute for each username from one
IP address. The username is stripped and case-folded first, so padded or recased
variants share one limit. Exceeding a limit returns a 429 with a JSON `detail`.

Like the HTML login, the API also counts the attempts for a username across all IP
addresses. Past 10 per minute it does not refuse the login, but requires an "I am
not a robot" checkbox: a 400 with an error for `i_am_not_a_robot`, which the client
sends as `true` with the next attempt. HIdP has no CAPTCHA. To add one, set
`rate_limited_serializer_class` on a subclass of `hidp.api.views.LoginView` to a
subclass of `hidp.api.serializers.RateLimitedLoginSerializer` with your own form.

Every API view has its own limits, except views that check the same secret: OTP
verification with an app code or a recovery code share one limit, and so do the two
ways to disable OTP. The limits are kept in the cache, so a project with more than
one process needs a shared cache such as Redis. See [Rate limiting](rate-limiting.md).

`POST logout/` ends the session.

### Registration and email verification

`POST signup/` with `{email, password, agreed_to_tos}` creates an account and sends
the verification email. The response has a pending `email_verify` step whether or not
the account already existed; an existing user is told by email instead. The endpoint
returns 404 when `REGISTRATION_ENABLED` is `False`.

`signup/`, `login/` and `email-verification/resend/` take an optional `next`: a path
on this site, or an absolute URL on its host. The link in the verification email
gets it as `?next=<path>`, so the frontend can continue there after verifying, for
example to an authorization request of HIdP's OIDC provider.

The verification email links to your frontend, with the token in the URL. The
frontend then:

1. `POST email-verification/verify/` with `{token}`, which responds with
   `{requires_name}`. It is `true` for a user created through an OIDC provider that
   did not supply a name.
2. `POST email-verification/confirm/` with `{token}`, plus `first_name` and
   `last_name` when required.

The user is not logged in by confirming. `POST email-verification/resend/` resends
the email to the user the session is waiting for. It responds with 204 whether or
not an email was sent.

### Password recovery

`POST password-reset/` with `{email}` responds with 204 whether or not an account
exists. A user with a password is sent a reset link, a user without one a link to
set one.

`POST password-reset/confirm/` with `{uidb64, token, new_password}` sets the new
password and responds with 204. It logs out every session of the user, and does not
log them in.

### Account management

These endpoints require a fully authenticated user.

| Endpoint | Behaviour |
| --- | --- |
| `GET`, `PATCH users/me/` | The user. Only `first_name` and `last_name` are writable by default. With the OIDC provider installed, an OAuth2 access token with the `profile` and `email` scopes can read the user, but not change it. |
| `POST password/change/` | `{old_password, new_password}`. The session stays logged in. |
| `POST password/set/` | `{new_password}`, for a user without a password. Only allowed within 5 minutes of logging in. |
| `GET email-change/` | The pending email change request, or 404. |
| `POST email-change/` | `{proposed_email, password}`. Replaces the pending request and emails both addresses. |
| `DELETE email-change/` | Cancels the pending request. |
| `POST email-change/confirm/` | `{token}` from either email. The address changes once both confirmed. |

The user object has `has_usable_password`, so the frontend can offer "change
password" or "set password" as appropriate.

### Two-factor authentication

| Endpoint | Behaviour |
| --- | --- |
| `GET otp/` | `{configured, recovery_codes_remaining}` |
| `GET otp/setup/` | `{secret, config_url, qr_code, recovery_codes}` for the unconfirmed device. Repeated calls return the same device. |
| `POST otp/setup/` | `{otp_token, confirm_stored_backup_tokens}`. Confirms the device and verifies the session. |
| `POST otp/verify/` | `{otp_token}` |
| `POST otp/verify/recovery-code/` | `{recovery_code}`. The code is used up, and the user is notified by email. |
| `POST otp/disable/` | `{otp_token}`. Removes the devices. |
| `POST otp/disable/recovery-code/` | `{recovery_code}`. Removes the devices. |
| `GET`, `POST otp/recovery-codes/` | The recovery codes. POST replaces them. |

Setup and verification are available to a partly authenticated user. The other
endpoints require a verified session when the OTP policy asks for one. A user who
has recovery codes but no authenticator app, for example after an administrator
removed a lost one, must verify with a recovery code before setting up a new app.
Which users must set up or verify OTP is decided by the
[OTP policy](one-time-passwords.md) middleware, for the API and the HTML views
alike.

### Logging in with an OIDC provider

Logging in with a provider [configured](configure-oidc-clients.md) for HIdP
redirects through the provider and HIdP's callback, and hands every page to the
frontend once `HIDP_FRONTEND_URLS` has `login`, `oidc_registration` and `oidc_link`
(see [the settings](#hidp_frontend_urls)). Include `hidp.config.headless_urls` (or
`hidp.config.urls`) for the callback.

1. `GET oidc/providers/` lists `[{key, name}]` for the login buttons.
2. `POST oidc/authenticate/<key>/` with an optional `next` responds with
   `{redirect_url}`, the authorization page of the provider. The frontend sends the
   browser there, with a full page load. HTTPS is required.
3. The provider returns to HIdP's callback, which redirects to:
   - `next` (or `/`), for an account that logs in with the provider. A user whose
     email address is not verified is sent the verification email instead, and
     redirected to `email_verification_required` (or `login`) with `next`; the
     session has a pending `email_verify` step.
   - `oidc_registration?token=…&next=…` for a first login.
   - `oidc_link?token=…&next=…` for a logged-in user who logs in with an account of
     the provider that is not linked yet.
   - `login?oidc_error=…`, with `next` for `account_exists`, when it fails.

On the registration page, `GET oidc/registration/?token=…` gives
`{provider: {key, name}, email, first_name, last_name, requires_name}`, and
`POST oidc/registration/` with `{token, agreed_to_tos}` creates the account. The
names default to the ones the provider sent; when it sent none, they are asked for
when the email address is verified. When the provider is
[trusted to verify email addresses](configure-oidc-clients.md#verified-email-addresses),
the user is logged in. Otherwise they are sent the verification email, with an
optional `next`, and the response has a pending `email_verify` step. The endpoint
returns 404 when `REGISTRATION_ENABLED` is `False`.

On the link page, `GET oidc/link/?token=…` gives `{provider, provider_email, email}`,
and `POST oidc/link/` with `{token}` links the account, which needs a fully
authenticated user. A user links one account per provider.

| `oidc_error` | Meaning |
| --- | --- |
| `account_exists` | The email address of the provider account has an account. The user logs in to it, then links the provider. |
| `request_expired` | The login took too long, or started in another session. |
| `unexpected_error` | The provider or the network failed. |
| `invalid_token` | The token of the step expired, or is not of this session. |
| `invalid_credentials` | The account is inactive, or a backend refused it. |
| `registration_disabled` | A first login while `REGISTRATION_ENABLED` is `False`. |

The tokens are in the URLs of the frontend pages, so give them the same care as the
email links (see [Settings](#hidp_frontend_urls)). The registration and link tokens
expire after 15 minutes, and work once.

#### Linked providers

| Endpoint | Behaviour |
| --- | --- |
| `GET oidc/connections/` | `[{key, name, linked, can_unlink}]` for every provider. `can_unlink` is false for the only way a user without a password logs in. |
| `DELETE oidc/connections/<key>/` | Unlinks the provider. |

To link a provider, the frontend starts a login with it while the user is logged in.

`POST password/set/` needs a login within the last 5 minutes. When it responds with
`reauthentication_required`, the frontend starts
`POST oidc/authenticate/<key>/` with `{reauthenticate: true, next}` for a linked
provider. The provider asks for the credentials again, and the user returns to
`next`.

### Errors

Errors use the shapes of Django REST framework's default exception handler:
`{field: [messages]}` for invalid input, with `non_field_errors` for errors about
the request as a whole, and `{detail}` for everything else. The endpoints keep these
shapes under a project-wide `EXCEPTION_HANDLER`, such as DRF Standardized Errors;
only `users/me/` uses it. Input errors carry the translated messages of the HTML
forms, and the rate limit and CSRF messages are translated too.

A rejected login or OTP request keeps its database writes, even with
`ATOMIC_REQUESTS`, so failed attempts still count: a wrong OTP code towards the
lockout of the device, a wrong password for listeners of `user_login_failed`. Other
requests roll back. Subclasses can change this with `keep_writes_on_invalid_input`.

A 403 that the client can act on carries a `code` next to the `detail`:

| Code | Returned by |
| --- | --- |
| `already_authenticated` | `signup/`, `oidc/registration/` |
| `invalid_credentials` | `oidc/registration/`, when a backend refuses the user of a verified email address. The account is not created. |
| `only_login_method` | `DELETE oidc/connections/<key>/` |
| `password_not_set` | `password/change/`, `POST email-change/` |
| `password_already_set` | `password/set/` |
| `reauthentication_required` | `password/set/`, when the user logged in more than 5 minutes ago. |
| `otp_not_configured` | `otp/verify/`, `otp/disable/` and their recovery code variants. |
| `otp_already_configured` | `otp/setup/` |
| `otp_verification_required` | `otp/setup/`, when the user has recovery codes and the session is not verified. |

## Settings

### `HIDP_FRONTEND_URLS`

The emails sent by the API link to your frontend. This setting maps each link to a
URL template, and is required when `hidp.api.urls` is included.

A relative template is joined to the URL of the request, so `"/verify/{token}/"`
works on every domain the project is served on. Because this uses the `Host` of the
request, `ALLOWED_HOSTS` must list only your own domains: with `"*"`, a request with
a forged `Host` header gets emails that link to the attacker's site. The HTML views
build their links the same way.

```python
HIDP_FRONTEND_URLS = {
    "email_verification": "/verify/{token}/",
    "password_reset": "/reset/{uidb64}/{token}/",
    "password_reset_request": "/reset/",
    "set_password": "/account/set-password/",
    "email_change_confirm": "/account/email/{token}/",
    "email_change_cancel": "/account/email/cancel/",
    "otp_management": "/account/two-factor/",
}
```

| Key | Placeholders | Links to |
| --- | --- | --- |
| `email_verification` | `{token}` | Confirming a new account. |
| `password_reset` | `{uidb64}`, `{token}` | Choosing a new password. |
| `password_reset_request` | | Requesting a password reset, linked from the "password changed" and "account exists" emails. |
| `set_password` | | Setting a password, for a user who has none. |
| `email_change_confirm` | `{token}` | Confirming an email change. |
| `email_change_cancel` | | Cancelling an email change. |
| `otp_management` | | Managing two-factor authentication. Required when `hidp.otp` is installed. |
| `otp_verify` | | Optional. Takes the place of the HTML OTP verification view in redirects. |
| `otp_setup` | | Optional. Takes the place of the HTML OTP setup view in redirects. |
| `login` | | Optional. The login page, for the errors of logging in with an OIDC provider. |
| `oidc_registration` | | Optional. Creating an account at the first login with an OIDC provider. |
| `oidc_link` | | Optional. Linking an OIDC provider to the logged-in user. |
| `email_verification_required` | | Optional. The page of the pending `email_verify` step after logging in with an OIDC provider. Defaults to `login`. |

Logging in with an OIDC provider hands off to the frontend when `login`,
`oidc_registration` and `oidc_link` are all set. HIdP adds the parameters of these
pages to their query.

Emails sent by the HTML views keep linking to the HTML views.

The `email_verification`, `password_reset` and `email_change_confirm` links carry a
token in the URL. Serve those frontend pages with `Referrer-Policy: no-referrer`, so
the token is not sent to other sites, and remove it from the address bar with
`history.replaceState` once the page has read it. The HTML views do the same by
moving the token into the session.

### `HIDP_API_USER_SERIALIZER`

The dotted path of the serializer for the user, in the authentication state and at
`users/me/`. It must be a subclass of `hidp.api.serializers.UserSerializer`:

```python
from hidp.api.serializers import UserSerializer


class ProjectUserSerializer(UserSerializer):
    class Meta(UserSerializer.Meta):
        fields = [*UserSerializer.Meta.fields, "role"]
```

Every field is read-only except those in `writable_fields`, which defaults to
`("first_name", "last_name")`. Widening it lets every logged-in user change those
fields about themselves, so never add a field such as `is_staff` or `is_superuser`.

When the setting cannot be imported, or does not name a subclass of
`UserSerializer`, the API logs an error and uses `UserSerializer`.

## Headless-only projects

A project can leave out `hidp.config.urls` and mount only the API:

- System check `hidp.E006` accepts the login endpoint of the API in place of the
  HTML login view.
- Set `LOGIN_URL` to the login page of your frontend, so `login_required` views,
  such as the Django admin, send users there. Redirect `admin/login/` to it as
  well: the admin's own login form has none of HIdP's rate limits.
- Set `otp_verify` and `otp_setup` in `HIDP_FRONTEND_URLS`, so the OTP middleware
  sends users of HTML views to your frontend. The original path is passed as `next`;
  check that it is a local path before redirecting back to it.
- With OIDC providers to log in with, include `hidp.config.headless_urls`. It
  mounts the views that the login redirects through at `login/oidc/`, the user
  endpoint for access tokens at `api/users/me/`, and HIdP's OIDC provider at `o/`
  when it is installed:

  ```python
  urlpatterns = [
      path("", include("hidp.config.headless_urls")),
      path("api/auth/", include("hidp.api.urls")),
  ]
  ```

  The OIDC views require HTTPS: behind a proxy, set `SECURE_PROXY_SSL_HEADER`.
- With HIdP's OIDC provider, set `OIDC_RP_INITIATED_REGISTRATION_URL` in
  `OAUTH2_PROVIDER` to the signup page of your frontend, see
  [Configure as OIDC provider](configure-as-oidc-provider.md).

## APIs that are not Django REST framework

The OTP middleware answers a Django REST framework view with the authentication
state as a JSON 401 instead of a redirect, and `RateLimitMiddleware` answers it
with a JSON 429. APIs built with something else, such as Django Ninja or views that
return `JsonResponse`, get the same responses when their paths are listed in
`HIDP_API_PATH_PREFIXES`:

```python
HIDP_API_PATH_PREFIXES = ["/api/v2/"]
```

A prefix must not cover pages that browsers navigate to, such as `/o/authorize/`
or the OIDC callback: they would answer with JSON instead of a redirect.

## System checks

| Id | Problem |
| --- | --- |
| `hidp.E011` | `hidp.api.urls` is included, and `HIDP_FRONTEND_URLS` is missing, not a dictionary, or lacks a required key. |
| `hidp.E012` | A URL template lacks a required placeholder. |
| `hidp.E013` | A URL template is not a string, or has a placeholder it cannot receive. |
| `hidp.E014` | `HIDP_API_USER_SERIALIZER` does not name a subclass of `UserSerializer`. |
| `hidp.E015` | `HIDP_FRONTEND_URLS` has some, but not all, of `login`, `oidc_registration` and `oidc_link`. |
| `hidp.E016` | `OIDC_RP_INITIATED_REGISTRATION_URL` does not resolve, while `prompt=create` is enabled. |
| `hidp.E017` | OIDC providers are configured and the OIDC endpoints of the API are mounted, but HIdP's OIDC callback is not. |
| `hidp.E018` | `HIDP_API_PATH_PREFIXES` is not a list of paths that start with a slash. |
| `hidp.W002` | An OIDC authentication backend does not accept `claims`, see [Configure OIDC Clients](configure-oidc-clients.md#authentication-backends). |
| `hidp.W003` | `HIDP_API_PATH_PREFIXES` covers a page that browsers navigate to. |

## OpenAPI Specification

The endpoints are described in the [OpenAPI Specification](./redoc-static.html){.external}.

## Limitations

- **Sessions only.** The API issues no tokens of its own, so the frontend must share
  a site with the API. Only `users/me/` also accepts access tokens of HIdP's OIDC
  provider, read-only.
- **No automatic login after email verification**, as in the HTML flow.
- **No session management.** The API cannot list or end the other sessions of a
  user.
- **Signup requires `agreed_to_tos`.** A project without terms of service can
  subclass `hidp.api.serializers.SignupSerializer` with
  `agreed_to_tos = serializers.HiddenField(default=True)`, and mount a subclass of
  `hidp.api.views.SignupView` that uses it.
- **Anonymous requests to protected endpoints get a 403**, the default of Django
  REST framework. Use `GET session/` to tell an anonymous session from a partly
  authenticated one.
