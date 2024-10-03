# Configure as OIDC Provider

To configure HIdP as an OpenID Connect (OIDC) Provider, please make sure you followed all the steps in
[Installation](project:./installation.md) and you have created a superuser.

:::{note}
The OIDC Provider part of HIdP is based on [Django OAuth Toolkit](https://django-oauth-toolkit.readthedocs.io/en/latest/)
:::

## Installation

Install with pip

```
pip install hidp[oidc_provider]
```

Add the following to `INSTALLED_APPS` in your Django settings:

```python
INSTALLED_APPS = [
    ...
    # Headless Identity Provider
    "oauth2_provider",
    "hidp.oidc_provider",
    "rest_framework",
    "hidp.api",
    ...
]
```

## Generate private key

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

### `/o/token/`
[TokenView](https://django-oauth-toolkit.readthedocs.io/en/latest/views/details.html#oauth2_provider.views.base.TokenView)

### `/o/userinfo/`

This view provides extra user details for the authenticated user, based on the requested scopes.

### `/o/.well-known/jwks.json`

This view provides details of the keys used to sign the JWTs generated for ID tokens,
so that clients are able to verify them.

### `/api/user/me/`

API endpoint to retrieve and update the user's basic information (first and last name).

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
