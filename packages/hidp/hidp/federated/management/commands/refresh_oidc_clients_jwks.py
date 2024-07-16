from django.core.management.base import BaseCommand

from ...oidc import jwks


class Command(BaseCommand):
    help = "Refresh the signing keys for all OIDC clients."

    def handle(self, *args, **options):
        jwks.refresh_registered_oidc_clients_jwks(stdout=self.stdout)
