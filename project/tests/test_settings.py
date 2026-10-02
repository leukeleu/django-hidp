import logging
import os
import warnings

from hidp_sandbox.settings import *  # noqa: F403 (* import)

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

# URL templates for the links in emails sent by the API
HIDP_FRONTEND_URLS = {
    "email_verification": "/frontend/verify/{token}/",
    "password_reset": "/frontend/reset/{uidb64}/{token}/",
    "password_reset_request": "/frontend/reset/",
    "set_password": "/frontend/set-password/",
    "email_change_confirm": "/frontend/change-email/{token}/",
    "email_change_cancel": "/frontend/change-email/cancel/",
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
