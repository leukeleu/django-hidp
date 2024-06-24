"""
Configuration for hidp.
"""

REQUIRED_APPS = [
    "hidp.accounts",
]

def configure_django(settings: dict):
    """
    Add hidp-specific configuration to the Django settings module.
    """
    settings.setdefault("INSTALLED_APPS", [])
    for app in REQUIRED_APPS:
        if app not in settings["INSTALLED_APPS"]:
            settings["INSTALLED_APPS"].append(app)

    settings["USE_TZ"] = True
    settings["AUTH_USER_MODEL"] = "accounts.User"

    # Login and logout settings
    settings["LOGIN_URL"] = "auth:login"

    # Default login and logout redirect URL
    settings["LOGIN_REDIRECT_URL"] = "/"
    settings["LOGOUT_REDIRECT_URL"] = "/"
