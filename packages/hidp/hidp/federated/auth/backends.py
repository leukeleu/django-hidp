from django.contrib.auth.backends import ModelBackend

from ...config.oidc_clients import get_oidc_client
from ..models import OpenIdConnection


class OIDCModelBackend(ModelBackend):
    def authenticate(
        self,
        request=None,
        provider_key=None,
        issuer_claim=None,
        subject_claim=None,
    ):
        if any(value is None for value in (provider_key, issuer_claim, subject_claim)):
            # None of the required parameters are provided,
            # skip authentication and let another backend handle it.
            return None

        # Find an OpenID connection. This always runs a query regardless whether
        # the provider_key is a registered OIDC provider or not.
        connection = OpenIdConnection.objects.get_by_provider_and_claims(
            provider_key=provider_key,
            issuer_claim=issuer_claim,
            subject_claim=subject_claim,
        )

        try:
            # Check if the provider_key is a registered OIDC provider
            get_oidc_client(provider_key)
        except KeyError:
            return None

        if connection:
            user = connection.user
            if self.user_can_authenticate(user):
                return user
        return None
