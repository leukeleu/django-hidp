import importlib
import string

from django.apps import apps
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

# Keys required in the HIDP_FRONTEND_URLS setting when the headless API is mounted,
# mapped to the placeholders their URL template must contain.
REQUIRED_FRONTEND_URLS = {
    "email_verification": {"token"},
    "password_reset": {"uidb64", "token"},
    "password_reset_request": set(),
    "set_password": set(),
    "email_change_confirm": {"token"},
    "email_change_cancel": set(),
}

REQUIRED_OTP_FRONTEND_URLS = {
    "otp_management": set(),
}

# Take the place of the HTML OTP views in redirects, when set.
OPTIONAL_FRONTEND_URLS = {
    "otp_verify": set(),
    "otp_setup": set(),
}


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
        " A headless project includes hidp.api.urls instead."
    ),
    id="hidp.E006",
)


@checks.register(Tags.settings)
def check_login_url(**kwargs):
    for url_name in ("hidp_accounts:login", "hidp_api:login"):
        try:
            reverse(url_name)
        except NoReverseMatch:
            continue
        return []
    return [E006]


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


def _frontend_url_placeholders(url_template):
    return {
        field_name
        for _, field_name, _, _ in string.Formatter().parse(url_template)
        if field_name is not None
    }


@checks.register(Tags.settings)
def check_api_frontend_urls(**kwargs):
    """Make sure `HIDP_FRONTEND_URLS` is configured when the headless API is mounted."""
    try:
        reverse("hidp_api:session")
    except NoReverseMatch:
        return []

    required_urls = REQUIRED_FRONTEND_URLS | (
        REQUIRED_OTP_FRONTEND_URLS if apps.is_installed("hidp.otp") else {}
    )
    frontend_urls = getattr(settings, "HIDP_FRONTEND_URLS", None)
    if frontend_urls is None:
        return [
            checks.Error(
                "HIDP_FRONTEND_URLS is not set. The headless API needs it for the"
                " links in the emails it sends.",
                hint=(
                    "Add HIDP_FRONTEND_URLS to your settings, with URL templates for:"
                    f" {', '.join(required_urls)}."
                ),
                id="hidp.E011",
            )
        ]
    if not isinstance(frontend_urls, dict):
        return [
            checks.Error(
                "HIDP_FRONTEND_URLS must be a dictionary of URL templates.",
                hint=(
                    "Map each of these keys to a URL template:"
                    f" {', '.join(required_urls)}."
                ),
                id="hidp.E011",
            )
        ]

    missing_keys = [key for key in required_urls if key not in frontend_urls]
    if missing_keys:
        return [
            checks.Error(
                "HIDP_FRONTEND_URLS is missing required keys.",
                hint=f"Add URL templates for: {', '.join(missing_keys)}.",
                id="hidp.E011",
            )
        ]

    errors = []
    for key, required_placeholders in (required_urls | OPTIONAL_FRONTEND_URLS).items():
        if key not in frontend_urls:
            continue
        url_template = frontend_urls[key]
        try:
            placeholders = _frontend_url_placeholders(url_template)
        except (TypeError, ValueError):
            placeholders = None
        if placeholders is None or placeholders - required_placeholders:
            allowed = ", ".join(
                f"{{{placeholder}}}" for placeholder in sorted(required_placeholders)
            )
            errors.append(
                checks.Error(
                    f"HIDP_FRONTEND_URLS[{key!r}] is not a valid URL template.",
                    hint=(
                        f"Use a string with only these placeholders: {allowed}."
                        if allowed
                        else "Use a string without placeholders."
                    ),
                    id="hidp.E013",
                )
            )
        elif missing := required_placeholders - placeholders:
            errors.append(
                checks.Error(
                    f"HIDP_FRONTEND_URLS[{key!r}] is missing required placeholders.",
                    hint="Add: "
                    + ", ".join(f"{{{placeholder}}}" for placeholder in sorted(missing))
                    + ".",
                    id="hidp.E012",
                )
            )
    return errors


@checks.register(Tags.settings)
def check_api_user_serializer(**kwargs):
    """Make sure `HIDP_API_USER_SERIALIZER` names a subclass of `UserSerializer`."""
    path = getattr(settings, "HIDP_API_USER_SERIALIZER", None)
    if not path or not apps.is_installed("hidp.api"):
        return []

    from hidp.api.serializers import import_user_serializer  # noqa: PLC0415

    try:
        import_user_serializer(path)
    except (ImportError, TypeError):
        pass
    else:
        return []
    return [
        checks.Error(
            f"HIDP_API_USER_SERIALIZER {path!r} is not an importable subclass of"
            " hidp.api.serializers.UserSerializer.",
            hint=(
                "Point it at a subclass of UserSerializer, or remove the setting."
                " The API uses UserSerializer until then."
            ),
            id="hidp.E014",
        )
    ]


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
