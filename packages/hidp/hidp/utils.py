import warnings

from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from django.conf import settings
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext_lazy as _

from .config import oidc_clients


def is_registration_enabled():
    if hasattr(settings, "REGISTRATION_ENABLED"):
        # Return the set value
        return settings.REGISTRATION_ENABLED
    else:
        # Preserve the default behavior, as it was before this release by returning
        # True if the setting is not set. This prevents breaking changes for
        # existing installations where the setting was not set and the default
        # behavior was to allow registration.
        warnings.warn(
            "The default value of the REGISTRATION_ENABLED setting will change "
            "from True to False in a future version of HIdP. Set REGISTRATION_ENABLED "
            "to True to maintain the current situation or to False to silence this "
            "warning.",
            PendingDeprecationWarning,
            stacklevel=2,
        )
        return True


def get_frontend_url(key, *, base_url):
    """Return the `HIDP_FRONTEND_URLS` template for `key`, joined to `base_url`."""
    return urljoin(base_url, settings.HIDP_FRONTEND_URLS[key])


# Logging in with an OIDC provider uses the frontend when all of these are set.
OIDC_FRONTEND_URL_KEYS = ("login", "oidc_registration", "oidc_link")


def is_headless_oidc():
    """Return whether logging in with an OIDC provider hands off to the frontend."""
    return all(has_frontend_url(key) for key in OIDC_FRONTEND_URL_KEYS)


def add_query_params(url, **params):
    """Return `url` with `params` added to its query, skipping `None`."""
    scheme, netloc, path, query, fragment = urlsplit(url)
    query = urlencode(
        [
            *parse_qsl(query, keep_blank_values=True),
            *((name, value) for name, value in params.items() if value is not None),
        ]
    )
    return urlunsplit((scheme, netloc, path, query, fragment))


def get_frontend_redirect_url(request, key, **params):
    """Return the frontend URL of `key` with `params` in its query, skipping `None`."""
    return add_query_params(
        get_frontend_url(key, base_url=request.build_absolute_uri("/")), **params
    )


def has_frontend_url(key):
    """Return whether `HIDP_FRONTEND_URLS` has a URL template for `key`."""
    return key in getattr(settings, "HIDP_FRONTEND_URLS", {})


def is_api_view(view_func):
    """Return whether `view_func` is a Django REST framework view."""
    view_class = getattr(view_func, "cls", None)
    if not isinstance(view_class, type):
        return False
    try:
        from rest_framework.views import APIView  # noqa: PLC0415
    except ImportError:
        return False
    return issubclass(view_class, APIView)


def get_local_redirect(request, url):
    """
    Return `url` as a path on this site, or `None` when it leads elsewhere.

    Accepts a path, or an absolute URL on the host of the request, such as the
    `next` that Django OAuth Toolkit builds for `prompt=create`.
    """
    if not url or not url_has_allowed_host_and_scheme(
        url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return None
    _scheme, _netloc, path, query, fragment = urlsplit(url)
    if not path.startswith("/"):
        return None
    return urlunsplit(("", "", path, query, fragment))


def get_api_path_prefixes():
    """Return the `HIDP_API_PATH_PREFIXES` setting: paths of APIs that are not DRF."""
    return tuple(getattr(settings, "HIDP_API_PATH_PREFIXES", ()))


def is_api_request(request, view_func=None):
    """
    Return whether `request` goes to an API, which gets JSON instead of a page.

    That is a Django REST framework view, or a path under one of the
    `HIDP_API_PATH_PREFIXES`, for APIs built with something else.
    """
    if view_func is not None and is_api_view(view_func):
        return True
    prefixes = get_api_path_prefixes()
    return bool(prefixes) and request.path_info.startswith(prefixes)


def get_account_management_links(user):
    """
    Get a list of account management links for the given user.

    This function returns a list of dictionaries representing navigation
    links for common account-related actions. These include editing
    account details, changing or setting a password, managing linked
    OpenID Connect (OIDC) services, and configuring two-factor authentication (2FA),
    depending on the user's capabilities and the enabled features in the application.

    Args:
        user: The currently authenticated user.

    Returns:
        list[dict]: A list of link dictionaries with 'url' and 'text' keys.
    """
    if not user.is_authenticated:
        return []

    links = [
        {
            "url": reverse("hidp_account_management:edit_account"),
            "text": _("Edit account"),
        },
        {
            "url": reverse("hidp_account_management:email_change_request"),
            "text": _("Change email address"),
        },
    ]

    if user.has_usable_password():
        links.append(
            {
                "url": reverse("hidp_account_management:change_password"),
                "text": _("Change password"),
            },
        )
    else:
        links.append(
            {
                "url": reverse("hidp_account_management:set_password"),
                "text": _("Set a password"),
            },
        )

    if oidc_clients.get_registered_oidc_clients():
        links.append(
            {
                "url": reverse("hidp_oidc_management:linked_services"),
                "text": _("Linked services"),
            },
        )

    if "hidp.otp" in settings.INSTALLED_APPS:
        links.append(
            {
                "url": reverse("hidp_otp_management:manage"),
                "text": _("Two-factor authentication"),
            },
        )

    return links
