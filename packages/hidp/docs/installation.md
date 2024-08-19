# Installation

HIdP can be installed in a couple of different ways, depending on your usecase.

## Install as standalone Django application

Create a new Django project and start a new app, for example `accounts`.

## Settings

First of all, make sure timezone support is enabled in your Django settings:

```python
USE_TZ = True
```

### `INSTALLED_APPS`

Add the following to `INSTALLED_APPS` in your Django settings:

```python
INSTALLED_APPS = [
    ...,
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "django.contrib.messages",
    # Headless Identity Provider
    "oauth2_provider",
    "hidp",
    "hidp.accounts",
    "hidp.federated",
    # Project
    "accounts",
    ...,
]
```

### `MIDDLEWARE`

Enable the following middlewares in your Django settings:

```python
MIDDLEWARE = [
    ...,
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
    ...,
]
```

### `AUTH_USER_MODEL`

Add a custom `User` model to the `accounts` app you just created, that inherits from HIdP's [``BaseUser``](project:./user-model.md).

```python models.py
from hidp.accounts.models import BaseUser

class User(BaseUser):
  ...
```

After defining the model, run `./manage.py makemigrations accounts`.

:::{warning}
Make sure to define your custom `User` model immediately, before running any migrations.
:::

Configure your custom user model in your Django settings, e.g.:

```python
AUTH_USER_MODEL = "accounts.User"
```

### Login settings

Configure the login url and redirect urls in your Django settings:

```python
LOGIN_URL = "hidp_accounts:login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"
```

### OAuth2 Provider

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

### OpenID Connect based login (social accounts)

To enable users to log in using an existing Google, Microsoft or any other provider that
supports OpenID connect, include the `OIDCModelBackend` in `AUTHENTICATION_BACKENDS`.

```python
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "hidp.federated.auth.backends.OIDCModelBackend",
]
```

and register the clients for the desired providers:

```python
from hidp.federated.providers.google import GoogleOIDCClient
from hidp.federated.providers.microsoft import MicrosoftOIDCClient

hidp_config.configure_oidc_clients(
    GoogleOIDCClient(client_id="your-client-id", client_secret="****"),
    MicrosoftOIDCClient(client_id="your-client-id"),
)
```

It is possible to write your own client if you need to support different providers.

### URLs

Include the HIdP URLs in your Django project's `ROOT_URLCONF` module, e.g. `urls.py`:

```python
from django.urls import include, path
from hidp.config import urls as hidp_urls

urlpatterns = [
    ...,
    path("", include(hidp_urls)),
    ...,
]
```

### Cache

HIdP requires a caching implementation, in order for the rate limits to properly work
and to store OIDC Provider signing keys. See [Django's cache framework](https://docs.djangoproject.com/en/5.0/topics/cache/#django-s-cache-framework).

For example a Redis cache:

```python
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379",
    },
}
```

We also recommend the cached session backend:

```python
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"
```

:::{note}
This requires Redis to be running locally or on a remote machine. See [Redis](https://docs.djangoproject.com/en/5.0/topics/cache/#redis)
for more information how to set it up.
:::

## Database migrations

Run the database migrations:

```bash
python manage.py migrate
```

## Create a superuser

Create a superuser to test the HIdP login:

```bash
python manage.py createsuperuser
```

## Test the installation

These settings should be enough to get the HIdP up and running. There are other Django settings that may influence the
HIdP behavior, so make sure to check the [Django documentation](https://docs.djangoproject.com/en/stable/) for
more information.

Run the Django development server:

```bash
python manage.py runserver
```

Open the browser and navigate to the login page, e.g. `http://localhost:8000/login/`.

If everything is set up correctly, you should see the login page and be able to log in with the superuser credentials
created earlier.
