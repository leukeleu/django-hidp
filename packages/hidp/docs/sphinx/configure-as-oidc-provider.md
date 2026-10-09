# Configure as OIDC Provider

To configure HIdP as an OpenID Connect (OIDC) Provider, please make sure you followed all the steps in
[Installation](project:./installation.md) and you have created a superuser.

:::{note}
The OIDC Provider part of HIdP is based on [Django OAuth Toolkit](https://django-oauth-toolkit.readthedocs.io/en/latest/)
:::

## Installation

Install with pip

```
pip install django-hidp[recommended,oidc_provider]
```

This will install HIdP with the recommended dependencies and the OIDC provider functionality. See 
[Installation Extras](project:installation-extras.md) for more information.

Add the following to `INSTALLED_APPS` in your Django settings:

```python
INSTALLED_APPS = [
    ...
    # Hello, ID Please
    "oauth2_provider",
    "hidp.oidc_provider",
    "rest_framework",
    "hidp.api",
    ...
]
```

## Configure Django OAuth Toolkit

HIdP uses Django OAuth Toolkit (DOT) to provide OIDC functionality.

For easy configuration, HIdP provides a helper function to generate the settings required by DOT.

The only required setting is the `OIDC_RSA_PRIVATE_KEY`, which is used to sign the tokens.
All other settings are set to the values preferred by HIdP.

### Generate private key

The OAuth2 / OIDC provider requires a private key to sign the tokens.

Use the following command to generate a private key:

```bash
openssl genrsa -out 'oidc.key' 4096
```

Store the private key in a secure location (keep it secret, out of version control etc.) and update the Django settings
to provide the contents of the private key to the OAuth2 provider:

```python
import pathlib

from hidp import config as hidp_config

OAUTH2_PROVIDER = hidp_config.get_oauth2_provider_settings(
    # Read the private key from a file.
    OIDC_RSA_PRIVATE_KEY=pathlib.Path("/path/to/oidc.key").read_text(),
)
```

:::{note}
Other ways to provide the private key are possible, e.g. using environment variables.
Use whatever method is most suitable for your deployment.
:::

For information on the settings provided by `get_oauth2_provider_settings` and instructions on how to add or override
the settings, refer to the [](#addingoverriding-django-oauth-toolkit-settings) section.

## Database migrations

Run the database migrations:

```bash
python manage.py migrate
```

## Add Application

Add the Django Admin to the urls of your HIdP app:

```python
from django.contrib import admin
from django.urls import include, path
from hidp.config import urls as hidp_urls

urlpatterns = [
    ...,
    path("", include(hidp_urls)),
    path("django-admin/", admin.site.urls),
    ...,
]
```

Log in to the Django admin of the HIdP app and add an application under
'Django OAuth Toolkit' with the following fields:

- **Client id**: A unique id to connect your OIDC Client with. This ID is also visible
to end users in URLs
- **Redirect uris**: At least one redirection endpoint where the server will redirect
to after authorization. This URL must also be provided by the OIDC client
for verification. For example, https://www.yourdomain.dev/_/oidc/callback/
- **Client type**: Public
- **Authorization grant type**: Authorization code
- **Skip authorization**: Yes (for trusted clients)
- **Algorithm**: RSA with SHA-2 256

:::{important}
Save the generated **Client secret** somewhere safe before saving the form, because the
secret will be hashed when you save the form.
:::

:::{note}
PKCE is required by default.
:::

## Provided URLs

### `/o/authorize`
[AuthorizationView](https://django-oauth-toolkit.readthedocs.io/en/latest/views/details.html#oauth2_provider.views.base.AuthorizationView)

#### Account creation with `prompt=create`

A client can ask for a new account with `prompt=create`
([OpenID Connect Prompt Create](https://openid.net/specs/openid-connect-prompt-create-1_0.html)).
An anonymous user is sent to the registration page, which returns to the
authorization request without `create` after signing up. A logged-in user continues
the authorization as usual. Django OAuth Toolkit 3.4 or later handles this, with the
`OIDC_RP_INITIATED_REGISTRATION_ENABLED` and `OIDC_RP_INITIATED_REGISTRATION_URL`
settings that `get_oauth2_provider_settings` sets to HIdP's registration page.

In [headless mode](headless.md), point it at the signup page of your frontend:

```python
OAUTH2_PROVIDER = hidp_config.get_oauth2_provider_settings(
    OIDC_RSA_PRIVATE_KEY=OIDC_RSA_PRIVATE_KEY
) | {
    "OIDC_RP_INITIATED_REGISTRATION_URL": "/signup",
}
```

The page gets the authorization request as an absolute URL on the same host in
`next`. When registration is disabled, `prompt=create` is refused with a 400
`invalid_request`, as is a request for an unknown client.

### `/o/token/`
[TokenView](https://django-oauth-toolkit.readthedocs.io/en/latest/views/details.html#oauth2_provider.views.base.TokenView)

### `/o/userinfo/`

This view provides extra user details for the authenticated user, based on the requested scopes.

### `/o/.well-known/jwks.json`

This view provides details of the keys used to sign the JWTs generated for ID tokens,
so that clients are able to verify them.

### `/api/users/me/`

API endpoint to retrieve the user's basic information, with an access token that
has the `profile` and `email` scopes. It is mounted when `hidp.api` is installed.
The [headless API](headless.md) is not: it is only served where you include
`hidp.api.urls`.

## Headless mode

In [headless mode](headless.md), the frontend shows the pages of the OIDC provider.

### Logging in

An anonymous authorization request redirects to `LOGIN_URL`, with the request as
`next`. Set it to the login page of your frontend. After logging in, and any pending
step such as two-factor authentication, the frontend goes to `next` with a full page
load: it is a URL of HIdP, which continues the authorization.

A request with `prompt=login` asks the user to log in again. Its `next` leaves out
`prompt=login`, so the login page must always show its form, also to a user who is
logged in already.

`UiLocalesMiddleware` stores the language of `ui_locales` in Django's language
cookie (`LANGUAGE_COOKIE_NAME`, `django_language` by default). With Django's
`LocaleMiddleware`, the API uses it for its messages and emails too. A frontend that
reads that cookie shows the pages in the language the application asked for.

### Consent and logging out

An application with `skip_authorization` is authorized without asking the user,
which suits your own applications. For other applications, and for confirming an
RP-initiated logout, set these keys of `HIDP_FRONTEND_URLS`:

```python
HIDP_FRONTEND_URLS = {
    ...,
    "oidc_provider_consent": "/authorize/",
    "oidc_provider_logout": "/logout/",
}
```

Instead of showing a page, the provider redirects to the URL with a `token`.
`GET oidc-provider/page/?token=…` of the [headless API](headless.md) responds with
what the page shows:

- `consent`: the `application` (`{name, client_id}`) asks for `scopes`
  (`[{scope, description}]`).
- `logout`: the `application`, when known, asks to log the user out.
- `error`: an `error` and `error_description` that could not be sent to the
  application, such as an unknown client.

The frontend posts a form to the `action` of the page, as a normal page load, with
the `fields` as hidden inputs, the `csrfmiddlewaretoken`, and `allow` set to `true`
when the user agrees. Leaving `allow` out refuses. The response redirects to the
application. Like HIdP's own pages, the frontend pages must not be shown in frames
of other sites: send `Content-Security-Policy: frame-ancestors 'none'`.

## Django REST Framework recommendations

If you are using HIdP as a standalone service, or integrating it in a Django project that doesn't use
Django REST Framework yet, we recommend [DRF Standardized Errors](https://pypi.org/project/drf-standardized-errors/)
to provide standardized error responses. In addition, we recommend disabling the browsable API unless you have a
specific need for it.

### Install DRF Standardized Errors

```shell
pip install drf-standardized-errors
```

### Update Django settings

```python
INSTALLED_APPS = [
    ...,
    "drf_standardized_errors",
    ...,
]

REST_FRAMEWORK = {
    ...,
    # Disable the browsable API
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    # Set DRF Standardized Errors as the default exception handler
    "EXCEPTION_HANDLER": "drf_standardized_errors.handler.exception_handler",
    ...,
}
```

For more information on the functionality and options of DRF Standardized Errors, refer to the [documentation](https://drf-standardized-errors.readthedocs.io/en/latest/).

The endpoints of the [headless API](headless.md) keep their documented error
responses under such an exception handler; `/api/users/me/` uses it.

## Adding/overriding Django OAuth Toolkit settings

To add to or override the settings provided by `get_oauth2_provider_settings` you can update the dictionary
returned by the function, for example to disable the OIDC logout prompt use the following code:

```python
OAUTH2_PROVIDER = hidp_config.get_oauth2_provider_settings(
    OIDC_RSA_PRIVATE_KEY=OIDC_RSA_PRIVATE_KEY
) | {
    "OIDC_RP_INITIATED_LOGOUT_ALWAYS_PROMPT": False,
}
```

The settings provided by `get_oauth2_provider_settings` are as follows:

```{eval-rst}
.. literalinclude:: ../../hidp/config/oauth2_provider.py
  :lines: 1-65
```

Refer to the [Django OAuth Toolkit documentation](https://django-oauth-toolkit.readthedocs.io/en/latest/settings.html)
for more information on the settings provided by DOT and a list of all available settings.

## Translations

If your application supports multiple languages, you can add support for the OIDC `ui_locales` parameter
using the `UiLocalesMiddleware` provided by HIdP. See the [Translations](project:./translations.md) documentation
for more information.
