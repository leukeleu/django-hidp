from django.apps import AppConfig

from ..apps import HidpChecksMixin


class AccountsConfig(HidpChecksMixin, AppConfig):
    name = "hidp.accounts"
    label = "hidp_accounts"
