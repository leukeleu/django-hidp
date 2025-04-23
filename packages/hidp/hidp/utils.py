import warnings

from django.conf import settings


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
