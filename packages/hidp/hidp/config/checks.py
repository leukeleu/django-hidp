import importlib

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import checks
from django.urls import NoReverseMatch, reverse

from ..accounts.models import BaseUser

REQUIRED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "hidp",
    "hidp.accounts",
    "hidp.csp",
    "hidp.federated",
]

OIDC_PROVIDER_REQUIRED_APPS = [
    "oauth2_provider",
    "hidp.oidc_provider",
    "rest_framework",
    "hidp.api",
]

OTP_REQUIRED_APPS = [
    "django_otp",
    "django_otp.plugins.otp_totp",
    "django_otp.plugins.otp_static",
    "hidp.otp",
]

REQUIRED_MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
]

OTP_REQUIRED_MIDDLEWARE = "django_otp.middleware.OTPMiddleware"


class Tags:
    dependencies = "dependencies"
    middleware = "middleware"
    settings = "settings"


# Make sure the required apps are installed
E001 = checks.Error(
    "INSTALLED_APPS does not include the required apps for HIdP to work.",
    hint="INSTALLED_APPS should include the following apps: {}.".format(
        ", ".join(f"{app_name!r}" for app_name in REQUIRED_APPS)
    ),
    id="hidp.E001",
)


@checks.register(Tags.dependencies)
def check_installed_apps(**kwargs):
    for app_name in REQUIRED_APPS:
        if app_name not in settings.INSTALLED_APPS:
            return [E001]
    return []


# Make sure the required middleware is included
E002 = checks.Error(
    "MIDDLEWARE does not include the required middleware for HIdP to work.",
    hint="MIDDLEWARE should include the following middleware: {}.".format(
        ", ".join(f"{middleware!r}" for middleware in REQUIRED_MIDDLEWARE)
    ),
    id="hidp.E002",
)


@checks.register(Tags.middleware)
def check_middleware(**kwargs):
    for middleware in REQUIRED_MIDDLEWARE:
        if middleware not in settings.MIDDLEWARE:
            return [E002]
    return []


# Storing timezone-aware datetime objects is crucial for correctly handling
# timestamps in tokens and other time-sensitive operations.
E003 = checks.Error(
    "USE_TZ is not set to True.",
    hint="Set USE_TZ to True.",
    id="hidp.E003",
)


@checks.register(Tags.settings)
def check_use_tz(**kwargs):
    if not settings.USE_TZ:
        return [E003]
    return []


# Make sure the user model is compatible with HIdP
E004 = checks.Error(
    "AUTH_USER_MODEL is not set to a subclass of hidp.accounts.models.BaseUser.",
    hint="Define your own subclass of BaseUser and set AUTH_USER_MODEL.",
    id="hidp.E004",
)


@checks.register(Tags.settings)
def check_user_model(**kwargs):
    user_model = get_user_model()
    if not issubclass(user_model, BaseUser):
        return [E004]
    return []


# Make sure Django OAuth Toolkit is configured
E005 = checks.Error(
    "OAUTH2_PROVIDER is not configured correctly.",
    hint="Use hidp.config.get_oauth2_provider_settings() to configure OAUTH2_PROVIDER.",
    id="hidp.E005",
)


def check_oauth2_provider(**kwargs):
    oauth2_provider_settings = getattr(settings, "OAUTH2_PROVIDER", None)
    if (
        oauth2_provider_settings is None
        or not isinstance(oauth2_provider_settings, dict)
        or "OIDC_RSA_PRIVATE_KEY" not in oauth2_provider_settings
    ):
        return [E005]
    return []


# Make sure the urls are configured correctly
E006 = checks.Error(
    "Unable to reverse the 'hidp_accounts:login' URL.",
    hint=(
        "Include hidp.config.urls in your ROOT_URLCONF,"
        " or define custom URLs using the 'hidp_accounts' namespace."
    ),
    id="hidp.E006",
)


@checks.register(Tags.settings)
def check_login_url(**kwargs):
    try:
        reverse("hidp_accounts:login")
    except NoReverseMatch:
        return [E006]
    return []


E008 = checks.Error(
    "INSTALLED_APPS does not include the required OIDC provider apps.",
    hint="INSTALLED_APPS should include the following apps: {}.".format(
        ", ".join(f"{app_name!r}" for app_name in OIDC_PROVIDER_REQUIRED_APPS)
    ),
    id="hidp.E008",
)


def check_oidc_provider_installed_apps(**kwargs):
    for app_name in OIDC_PROVIDER_REQUIRED_APPS:
        if app_name not in settings.INSTALLED_APPS:
            return [E008]
    return []


if importlib.util.find_spec("oauth2_provider") is not None:
    # Only enable the OIDC provider checks if OAuth2 Provider is installed
    checks.register(Tags.settings)(check_oauth2_provider)
    checks.register(Tags.dependencies)(check_oidc_provider_installed_apps)


# Make sure the required apps for OTP are installed
E009 = checks.Error(
    "INSTALLED_APPS does not include the required OTP apps.",
    hint="INSTALLED_APPS should include the following apps: {}.".format(
        ", ".join(f"{app_name!r}" for app_name in OTP_REQUIRED_APPS)
    ),
    id="hidp.E009",
)


@checks.register(Tags.dependencies)
def check_otp_installed_apps(**kwargs):
    if "hidp.otp" in settings.INSTALLED_APPS:
        for app_name in OTP_REQUIRED_APPS:
            if app_name not in settings.INSTALLED_APPS:
                return [E009]
    return []


# Make sure the required middleware for OTP is included
E010 = checks.Error(
    "MIDDLEWARE does not include the required middleware for OTP to work.",
    hint=(
        f'Add "{OTP_REQUIRED_MIDDLEWARE}" middleware after "AuthenticationMiddleware".'
    ),
    id="hidp.E010",
)


@checks.register(Tags.middleware)
def check_otp_middleware(**kwargs):
    if (
        "hidp.otp" in settings.INSTALLED_APPS
        and OTP_REQUIRED_MIDDLEWARE not in settings.MIDDLEWARE
    ):
        return [E010]
    return []


# If django-otp is installed but hidp.otp is not, show a warning
W001 = checks.Warning(
    "django-otp is installed but hidp.otp is not in INSTALLED_APPS.",
    hint="Consider adding 'hidp.otp' to INSTALLED_APPS for a more complete OTP"
    " implementation.",
    id="hidp.W001",
)


@checks.register(Tags.dependencies)
def check_hidp_otp_installed_apps_when_django_otp_installed(**kwargs):
    if (
        importlib.util.find_spec("django_otp") is not None
        and "hidp.otp" not in settings.INSTALLED_APPS
    ):
        return [W001]
    return []
