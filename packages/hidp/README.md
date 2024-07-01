# Headless Identity Provider

Headless Identity Provider (HIdP).

## Installation

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
    "oauth2_provider",
    "hidp",
    "hidp.accounts",
    ...,
]
```

### `MIDDLEWARE`

Enable the following middlewares in your Django settings:

```python
MIDDLEWARE = [
    ...,
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    ...,
]
```

### `AUTH_USER_MODEL`

Configure a custom user model in your Django settings, e.g.:

```python
AUTH_USER_MODEL = "hidp_accounts.User"
```

Note: Extending the HIdP user model is also possible. If you intend to extend the user model, make sure to do this
immediately, before running any migrations.

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

Note:
Other ways to provide the private key are possible, e.g. using environment variables.
Use whatever method is most suitable for your deployment.

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
 
### Database migrations

Run the database migrations:

```bash
python manage.py migrate
```

### Create a superuser

Create a superuser to test the HIdP login:

```bash
python manage.py createsuperuser
```

### Test the installation

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

