from contextlib import suppress

from django.urls import NoReverseMatch, reverse, reverse_lazy


def get_registration_url(lazy=True):
    """
    Get the registration URL for the application.

    This function attempts to resolve the registration URL using the reverse
    function. If the URL cannot be resolved, it returns None.

    Returns:
        str | None: The registration URL if available, None otherwise.
    """
    resolver = reverse_lazy if lazy else reverse

    with suppress(NoReverseMatch):
        return reverse("hidp_accounts_registration:register")


def get_tos_url(lazy=True):
    """
    Get the Terms of Service URL for the application.

    This function attempts to resolve the Terms of Service URL using the reverse
    function. If the URL cannot be resolved, it returns None.

    Returns:
        str | None: The Terms of Service URL if available, None otherwise.
    """
    resolver = reverse_lazy if lazy else reverse

    with suppress(NoReverseMatch):
        return reverse_lazy("hidp_accounts_registration:tos")
