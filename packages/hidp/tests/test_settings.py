import logging
import os
import warnings

from pathlib import Path

from hidp import config as hidp_config

# Enable all warnings
warnings.resetwarnings()
# Warn only once per module
warnings.simplefilter("module")
# Redirect warnings output to the logging system
logging.captureWarnings(capture=True)

# Disable all log output, except warnings
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "null": {"class": "logging.NullHandler"},
    },
    "loggers": {
        "": {
            "handlers": ["null"],
        },
        "py.warnings": {
            "handlers": ["console"],
            "level": "WARNING",
        },
    },
}

# Repository root directory
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent

# Shared var directory (for logs, cache, etc.)
VAR_DIR = BASE_DIR / "var"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "rest_framework",
    "oauth2_provider",
    "hidp",
    "hidp.accounts",
    "hidp.api",
    "hidp.csp",
    "hidp.federated",
    "hidp.oidc_provider",
    "hidp.otp",
    "django_otp",
    "django_otp.plugins.otp_static",
    "django_otp.plugins.otp_totp",
    # Custom user model
    "tests.custom_user",
    # Custom makemessages command
    "tests.translations",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
    "hidp.oidc_provider.middleware.UiLocalesMiddleware",
    "django_otp.middleware.OTPMiddleware",
]

USE_TZ = True

AUTH_USER_MODEL = "custom_user.CustomUser"

# Custom authentication backend
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "hidp.federated.auth.backends.OIDCModelBackend",
]

# Login and logout settings
LOGIN_URL = "hidp_accounts:login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
            ],
        },
    }
]

OAUTH2_PROVIDER = hidp_config.get_oauth2_provider_settings(
    OIDC_RSA_PRIVATE_KEY=(VAR_DIR / "oidc.key").read_text(),
)

# Test key
SECRET_KEY = "secret-key-only-for-testing"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "postgres" if "CI" in os.environ else "test_hidp",
        "USER": "postgres",
        "PASSWORD": "postgres",
        "HOST": "localhost" if "CI" in os.environ else "postgres",
    }
}

ALLOWED_HOSTS = ["*"]

# Disable caches
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.dummy.DummyCache",
    }
}

# Enable unsafe but fast hashing, we're just testing anyway
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.MD5PasswordHasher",
]

ROOT_URLCONF = "hidp.config.urls"

# Help Django find and update HIdP's message catalogs
LOCALE_PATHS = [
    BASE_DIR / "packages" / "hidp" / "hidp" / "locale",
]
