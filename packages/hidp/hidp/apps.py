from django.apps import AppConfig


class HidpChecksMixin:
    def ready(self):  # noqa: PLR6301 (no-self-use)
        # registers checks
        from .config import checks  # noqa: F401, PLC0415


class AccountsConfig(HidpChecksMixin, AppConfig):
    name = "hidp"
