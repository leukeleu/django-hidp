from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import checks
from django.urls import NoReverseMatch, reverse

from hidp.accounts.models import BaseUser

REQUIRED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
    "oauth2_provider",
    "hidp",
    "hidp.accounts",
    "hidp.federated",
]

REQUIRED_MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "hidp.rate_limit.middleware.RateLimitMiddleware",
]


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
)


@checks.register(Tags.settings)
def check_use_tz(**kwargs):
    if not settings.USE_TZ:
        return [E003]
    return []


# Make sure the user model is compatible with HIdP
E004 = checks.Error(
    "AUTH_USER_MODEL is not set to (a subclass of) hidp.accounts.models.BaseUser.",
    hint="Set AUTH_USER_MODEL to 'hidp_accounts.User'.",
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
)


@checks.register(Tags.settings)
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
)


@checks.register(Tags.settings)
def check_login_url(**kwargs):
    try:
        reverse("hidp_accounts:login")
    except NoReverseMatch:
        return [E006]
    return []
