import logging
import os
import warnings

from hidp.settings import *  # noqa: F403 (* import)

warnings.resetwarnings()
warnings.simplefilter("module")

logging.captureWarnings(capture=True)

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
