# Installation

Headless Identity Provider is an all-in-one solution for your user management needs.

HIdP provides all the default Django authentication functionalities and more:
- Registration (including email verification)
- OpenID Connect (OIDC) Clients (Google and Microsoft included)
- Rate limiting
- Content Security Policy (see [Content Security Policy](project:content-security-policy.md))
- Can be used as a standalone OpenID Connect (OIDC) provider (see [Configure as Identity Provider](project:configure-as-oidc-provider.md))


## Install with pip
```
pip install hidp
```

## Settings
:::{note}
It is recommended to add a new app, for example `accounts`, where you can customize HIdP's models, views and templates.
:::

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
    # Headless Identity Provider
    "hidp",
    "hidp.accounts",
    "hidp.csp",
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

:::{note}
HIdP comes with a set of extra password validators that can be added to
`settings.AUTH_PASSWORD_VALIDATORS` if desired. See [Password Validators](project:password-validation.md)
for more information.

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

It is possible to write your own client if you need to support different providers,
see [Adding support for other OIDC Providers](project:configure-oidc-clients.md#adding-support-for-other-oidc-providers).

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

## Templates

HIdP comes with a set of templates that can be overridden in your project.

See [Customizing Templates](project:customizing-templates.md) for more information.
