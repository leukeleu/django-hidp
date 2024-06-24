"""
Configuration for django.contrib.auth.
"""

REQUIRED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
]

REQUIRED_MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]

def configure_django(settings: dict):
    """
    Add the necessary configuration for django.contrib.auth to the project.

    Arguments:
        settings: dict
            The globals() dictionary from the project's settings module.
            This dictionary will be modified in place.
    """
    settings.setdefault("INSTALLED_APPS", [])
    for app in REQUIRED_APPS:
        if app not in settings["INSTALLED_APPS"]:
            settings["INSTALLED_APPS"].append(app)

    settings.setdefault("MIDDLEWARE", [])
    for middleware in REQUIRED_MIDDLEWARE:
        if middleware not in settings["MIDDLEWARE"]:
            settings["MIDDLEWARE"].append(middleware)
