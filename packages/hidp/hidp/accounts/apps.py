from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "hidp.accounts"
    label = "hidp_accounts"

    def ready(self):  # noqa: PLR6301 (no-self-use)
        # registers checks
        from ..config import checks  # noqa: F401, PLC0415
