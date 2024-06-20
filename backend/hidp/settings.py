import ipaddress
import json
import os

from configparser import ConfigParser
from datetime import timedelta
from pathlib import Path

# Project directory (where settings.py is)
PROJECT_DIR = Path(__file__).resolve().parent

# Repository root directory
BASE_DIR = PROJECT_DIR.parent.parent

# Shared var directory (for logs, cache, etc.)
VAR_DIR = BASE_DIR / "var"

# Read configuration from ini file

config = ConfigParser(converters={"literal": json.loads}, interpolation=None)
config.read(
    [
        os.environ.get("APP_SETTINGS", PROJECT_DIR / "local.ini"),
        PROJECT_DIR / "local.ini",
    ]
)

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = config.getliteral("app", "secret_key")

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = config.getboolean("app", "debug", fallback=False)

ALLOWED_HOSTS = config.getliteral("app", "allowed_hosts")

# Trust X-Forwarded-Host header in development
USE_X_FORWARDED_HOST = DEBUG

# Security settings
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_CONTENT_TYPE_NOSNIFF = True  # Adds 'X-Content-Type-Options: nosniff' header
SECURE_BROWSER_XSS_FILTER = True  # Adds 'X-XSS-Protection: 1; mode=block' header
X_FRAME_OPTIONS = "DENY"  # Don't allow this site to be framed
SECURE_REFERRER_POLICY = (
    "strict-origin, strict-origin-when-cross-origin"  # Adds 'Referrer-Policy' header
)
SILENCED_SYSTEM_CHECKS = [
    # These are all handled by nginx, so Django doesn't need to worry about them
    "security.W004",  # You have not set a value for the SECURE_HSTS_SECONDS setting
    "security.W008",  # SECURE_SSL_REDIRECT setting is not set to True
    *config.getliteral("app", "silenced_system_checks", fallback=[]),
]

# Application definition

INSTALLED_APPS = [
    "bandit",
    "leukeleu_django_checks",
    # Django
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Django REST Framework
    "rest_framework",
    "django_filters",
    # Django OAuth Toolkit
    "oauth2_provider",
    # Headless Identity Provider
    "hidp.accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "hidp.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            str(PROJECT_DIR / "../templates"),
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "hidp.wsgi.application"

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "HOST": config.getliteral("app", "db_host", fallback=""),
        "NAME": config.getliteral("app", "db_name"),
        "USER": config.getliteral("app", "db_user"),
        "OPTIONS": {
            "passfile": Path("~/.pgpass").expanduser(),
        },
    }
}

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Custom user model
AUTH_USER_MODEL = "accounts.User"

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",  # noqa: E501
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]

# Login and logout settings
LOGIN_URL = "auth:login"

# Default login and logout redirect URL
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "nl-nl"

TIME_ZONE = "Europe/Amsterdam"

USE_I18N = True

USE_TZ = True

# Media files (user uploads)

MEDIA_URL = "/media/"

if DEBUG:
    # MEDIA_ROOT defaults to VAR_DIR/public/media/ in debug mode
    MEDIA_ROOT = config.getliteral(
        "app", "media_root", fallback=str(VAR_DIR / "public/media")
    )
else:
    # Require MEDIA_ROOT to be configured
    MEDIA_ROOT = config.getliteral("app", "media_root")

# File upload permissions
# https://docs.djangoproject.com/en/4.2/ref/settings/#file-upload-permissions
FILE_UPLOAD_PERMISSIONS = 0o644

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "/static/"

if DEBUG:
    # STATIC_ROOT defaults to VAR_DIR/public/static/ in debug mode
    STATIC_ROOT = config.getliteral(
        "app", "static_root", fallback=str(VAR_DIR / "public/static")
    )
else:
    # Require STATIC_ROOT to be configured
    STATIC_ROOT = config.getliteral("app", "static_root")

# File storage
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage",
    },
}

# Email backends
EMAIL_BANDIT = config.getliteral("app", "email_bandit", fallback=False)

if DEBUG:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    EMAIL_HOST = config.getliteral("app", "email_host", fallback="localhost")
    EMAIL_PORT = config.getliteral("app", "email_port", fallback=25)
    EMAIL_HOST_USER = config.getliteral("app", "email_host_user", fallback="")
    EMAIL_HOST_PASSWORD = config.getliteral("app", "email_host_password", fallback="")
    EMAIL_USE_TLS = config.getliteral("app", "email_use_tls", fallback=False)
    EMAIL_USE_SSL = config.getliteral("app", "email_use_ssl", fallback=False)

    if EMAIL_BANDIT:
        EMAIL_BACKEND = "bandit.backends.smtp.HijackSMTPBackend"
        BANDIT_EMAIL = config.getliteral("app", "bandit_email")
        BANDIT_WHITELIST = config.getliteral(
            "app", "bandit_whitelist", fallback=["leukeleu.nl"]
        )

DEFAULT_FROM_EMAIL = config.getliteral("app", "default_from_email")

# Sentry

SENTRY_DSN = config.getliteral("app", "sentry_dsn", fallback=None)
SENTRY_ENVIRONMENT = config.getliteral("app", "sentry_environment")

if SENTRY_DSN and SENTRY_ENVIRONMENT:
    import sentry_sdk

    from sentry_sdk.integrations.django import DjangoIntegration

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=SENTRY_ENVIRONMENT,
        integrations=[DjangoIntegration()],
    )


class InternalIPList:
    """
    A fake list that checks if a given ip address
    is local (loopback) or internal (private)
    """

    def __contains__(self, item):
        address = ipaddress.ip_address(item)
        return address.is_loopback or address.is_private


if DEBUG:
    INTERNAL_IPS = InternalIPList()


# Django OAuth Toolkit

if DEBUG:
    # Read the OIDC RSA private key from a file in debug mode
    # This file is generated by ../entrypoint.sh
    _OIDC_RSA_PRIVATE_KEY = (VAR_DIR / "oidc.key").read_text()
else:
    # Require OIDC_RSA_PRIVATE_KEY to be configured in staging and production
    _OIDC_RSA_PRIVATE_KEY = config.getliteral("app", "oidc_rsa_private_key")

OAUTH2_PROVIDER = {
    # The number of seconds an access token remains valid.
    # Requesting a protected resource after this duration will fail.
    # Keep this value high enough so clients can cache the token for
    # a reasonable amount of time.
    #
    # Default is 1 hour (3600 seconds).
    "ACCESS_TOKEN_EXPIRE_SECONDS": timedelta(hours=12).total_seconds(),
    # The number of seconds an authorization code remains valid.
    # Requesting an access token after this duration will fail.
    # RFC6749 Section 4.1.2 recommends a 10 minute (600 seconds) duration.
    #
    # Default is 1 minute (60 seconds).
    "AUTHORIZATION_CODE_EXPIRE_SECONDS": timedelta(minutes=10).total_seconds(),
    # The number of seconds before a refresh token gets removed from the database
    # by the cleartokens management command.
    #
    # NOTE: This value is completely ignored when validating refresh tokens.
    #
    # If cleartokens runs daily the maximum delay before a refresh token
    # is removed is REFRESH_TOKEN_EXPIRE_SECONDS + 1 day.
    #
    # Default is None (never remove refresh tokens).
    "REFRESH_TOKEN_EXPIRE_SECONDS": timedelta(days=90).total_seconds(),
    # The number of seconds between when a refresh token is first used
    # and when it is expired.
    # The most common case of this for this is native mobile applications
    # that run into issues of network connectivity during the refresh cycle
    # and are unable to complete the full request/response life cycle.
    # Without a grace period the application only has a consumed
    # refresh token and the only recourse is to have the user re-authenticate.
    #
    # Default is 0 (no grace period).
    "REFRESH_TOKEN_GRACE_PERIOD_SECONDS": timedelta(minutes=10).total_seconds(),
    "OIDC_ENABLED": True,  # OpenID Connect is not enabled by default
    # The RSA private key used to sign OpenID Connect ID Tokens
    # This key is generated by ../entrypoint.sh in development.
    # For deployment this key should be provided using a secret.
    # Generate a new key using:
    # openssl genrsa -out 'oidc.key' 4096
    "OIDC_RSA_PRIVATE_KEY": _OIDC_RSA_PRIVATE_KEY,
    # A list of scopes that can be requested by clients, with descriptions.
    "SCOPES": {
        # Default OpenID Connect scope
        # https://openid.net/specs/openid-connect-basic-1_0.html#Scopes
        "openid": "OpenID Connect",
        # OpenID Connect profile scope
        "profile": "View basic profile information",
        # OpenID Connect email scope
        "email": "View email address",
    },
    "DEFAULT_SCOPES": ["openid"],
    # Custom OAuth2Validator that maps OIDC scopes to the correct user attributes
    "OAUTH2_VALIDATOR_CLASS": "hidp.accounts.oauth_validators.OAuth2Validator",
}

# Remove the _OIDC_RSA_PRIVATE_KEY from the global namespace
del _OIDC_RSA_PRIVATE_KEY

# Django REST Framework

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}
