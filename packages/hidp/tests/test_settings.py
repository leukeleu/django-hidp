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
    "django.contrib.messages",
    "oauth2_provider",
    "hidp",
    "hidp.accounts",
    "hidp.federated",
    "tests.custom_user",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
]

USE_TZ = True

AUTH_USER_MODEL = "custom_user.CustomUser"

# Login and logout settings
LOGIN_URL = "hidp_accounts:login"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
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
        "NAME": "test_hidp",
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
