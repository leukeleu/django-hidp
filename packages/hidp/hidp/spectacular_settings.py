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
    # drf spectacular for generating OpenAPI specification
    "drf_spectacular",
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

# URLs/URL templates for urls sent in emails
EMAIL_VERIFICATION_URL = "email_verification_url/{token}/"
PASSWORD_CHANGED_URL = "password_changed_url/"  # noqa: S105
PASSWORD_RESET_URL = "password_reset_url/{uidb64}/{token}/"  # noqa: S105
SET_PASSWORD_URL = "set_password_url/"  # noqa: S105

AUTH_USER_MODEL = "custom_user.CustomUser"

ROOT_URLCONF = "hidp.config.urls"

SECRET_KEY = "secret-key-only-spectacular"  # noqa: S105

USE_TZ = True

REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
}

SPECTACULAR_SETTINGS = {
    "TITLE": "HIdP",
    "DESCRIPTION": "Hello, ID Please",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
}


SILENCED_SYSTEM_CHECKS = [
    # oauth_provider doesn't need to be configured for generating OpenAPI
    # specification
    "hidp.E005",
]
