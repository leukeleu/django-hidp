from django.apps import AppConfig

from ..apps import HidpChecksMixin


class APIConfig(HidpChecksMixin, AppConfig):
    name = "hidp.api"
    label = "hidp_api"
