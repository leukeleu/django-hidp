from django.conf import settings


def is_registration_enabled():
    return getattr(settings, "REGISTRATION_ENABLED", False)
