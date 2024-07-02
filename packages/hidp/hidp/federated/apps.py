from django.apps import AppConfig

from ..apps import HidpChecksMixin


class FederatedConfig(HidpChecksMixin, AppConfig):
    name = "hidp.federated"
    label = "hidp_federated"
