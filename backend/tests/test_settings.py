import logging
import os
import warnings

from pathlib import Path

from hidp import config as hidp_config

warnings.resetwarnings()
warnings.simplefilter("module")

logging.captureWarnings(capture=True)

# Project directory (where settings.py is)
PROJECT_DIR = Path(__file__).resolve().parent

# Repository root directory
BASE_DIR = PROJECT_DIR.parent.parent

# Shared var directory (for logs, cache, etc.)
VAR_DIR = BASE_DIR / "var"

# Disable all log output, except warnings
LOGGING = {
    "version": 1,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
        "null": {"class": "logging.NullHandler"},
    },
    "loggers": {
        "": {"handlers": ["null"]},
        "py.warnings": {"handlers": ["console"], "level": "WARNING"},
    },
}

# Test key
SECRET_KEY = "secret-key-only-for-testing"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "postgres",
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

ROOT_URLCONF = "tests.test_urls"

hidp_config.configure_django(
    globals(),
    OIDC_RSA_PRIVATE_KEY=(VAR_DIR / "oidc.key").read_text()
)
