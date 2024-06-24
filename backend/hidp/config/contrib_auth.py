REQUIRED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.sessions",
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
