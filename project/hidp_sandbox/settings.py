import ipaddress
import json
import os

from configparser import ConfigParser
from pathlib import Path

from hidp import config as hidp_config
from hidp.federated.providers.google import GoogleOIDCClient
from hidp.federated.providers.microsoft import MicrosoftOIDCClient

from .oidc_providers.oidc_certification import OIDCCertificationProvider

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
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.staticfiles",
    # Django REST Framework
    "rest_framework",
    "django_filters",
    # Django OAuth Toolkit
    "oauth2_provider",
    # Django OTP
    "django_otp",
    "django_otp.plugins.otp_static",
    "django_otp.plugins.otp_totp",
    # Headless Identity Provider
    "hidp",
    "hidp.accounts",
    "hidp.api",
    "hidp.csp",
    "hidp.federated",
    "hidp.oidc_provider",
    "hidp.otp",
    # Project
    "hidp_sandbox.accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_otp.middleware.OTPMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
    "hidp.otp.middleware.OTPVerificationRequiredIfConfiguredMiddleware",
    "hidp.otp.middleware.OTPSetupRequiredIfStaffUserMiddleware",
]

ROOT_URLCONF = "hidp_sandbox.urls"

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
            ],
        },
    },
]

WSGI_APPLICATION = "hidp_sandbox.wsgi.application"

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

# Cache settings

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": config.getliteral("app", "redis_cache_connection"),
    }
}

# Custom user model
AUTH_USER_MODEL = "accounts.User"

# Custom authentication backend
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "hidp.federated.auth.backends.OIDCModelBackend",
]

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
    {
        "NAME": "hidp.accounts.password_validation.DigitValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.UppercaseValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.LowercaseValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.SymbolValidator",
    },
]

# Login and logout settings
LOGIN_URL = "hidp_accounts:login"

# Default login and logout redirect URL
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# Faster reads by caching session data
SESSION_ENGINE = "django.contrib.sessions.backends.cached_db"

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "nl-nl"
LANGUAGES = [
    ("nl", "Nederlands"),
    ("en", "English"),
]

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
        BANDIT_WHITELIST = config.getliteral("app", "bandit_whitelist", fallback=[])

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
    """Fake list of all local (loopback) and internal (private) IP addresses."""

    def __contains__(self, item):
        address = ipaddress.ip_address(item)
        return address.is_loopback or address.is_private


if DEBUG:
    INTERNAL_IPS = InternalIPList()

# HIdP

# The RSA private key used to sign OpenID Connect ID Tokens
if DEBUG:
    # Read the OIDC RSA private key from a file in debug mode
    # This file is generated by ../entrypoint.sh
    _OIDC_RSA_PRIVATE_KEY = (VAR_DIR / "oidc.key").read_text()
else:
    # Require OIDC_RSA_PRIVATE_KEY to be configured in staging and production
    # Generate a new key using: penssl genrsa -out 'oidc.key' 4096
    _OIDC_RSA_PRIVATE_KEY = config.getliteral("app", "oidc_rsa_private_key")

# Configure OAUTH2_PROVIDER as required by the HIdP application
OAUTH2_PROVIDER = hidp_config.get_oauth2_provider_settings(
    OIDC_RSA_PRIVATE_KEY=_OIDC_RSA_PRIVATE_KEY
)

# Remove the _OIDC_RSA_PRIVATE_KEY from the global namespace
del _OIDC_RSA_PRIVATE_KEY

# Configure OIDC Clients for the HIdP application
oidc_clients = [
    GoogleOIDCClient(
        client_id=config.getliteral("app", "google_oidc_client_id"),
        client_secret=config.getliteral("app", "google_oidc_client_secret"),
        callback_base_url=config.getliteral(
            "app", "google_oidc_callback_base_url", fallback=None
        ),
    ),
    MicrosoftOIDCClient(
        client_id=config.getliteral("app", "microsoft_oidc_client_id"),
        callback_base_url=config.getliteral(
            "app", "microsoft_oidc_callback_base_url", fallback=None
        ),
    ),
]

if config.getboolean("app", "enable_oidc_certification_client", fallback=False):
    oidc_clients.append(
        OIDCCertificationProvider(
            client_id="oidc_cert",
            client_secret="not-a-secret",  # noqa: S106 (not a secret)
        )
    )

hidp_config.configure_oidc_clients(*oidc_clients)

# Django REST Framework

REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
    "DEFAULT_RENDERER_CLASSES": ["rest_framework.renderers.JSONRenderer"],
}

REGISTRATION_ENABLED = True
