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

AUTH_USER_MODEL = "custom_user.CustomUser"

ROOT_URLCONF = "hidp.config.urls"

SECRET_KEY = "secret-key-only-spectacular"  # noqa: S105

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
