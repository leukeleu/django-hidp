import warnings

from django.conf import settings
from django.urls import reverse
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
