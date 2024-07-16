from django.contrib.auth.backends import ModelBackend

from ...config.oidc_clients import get_oidc_client
from ..models import OpenIdConnection


class OIDCModelBackend(ModelBackend):
    def authenticate(  # noqa: PLR6301 (could be staticmethod)
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

        try:
            # Check if the provider_key is a registered OIDC provider
            get_oidc_client(provider_key)
        except KeyError:
            # Run a database query to reduce the timing difference between
            # a registered and an unregistered OIDC provider.
            # This should never happen in real-world scenarios, but it's
            # a good practice if it somehow does.
            OpenIdConnection.objects.filter(
                provider_key=provider_key,
                issuer_claim=issuer_claim,
                subject_claim=subject_claim,
            ).exists()
            return None

        try:
            # Return the user associated with the OpenID connection
            # matching the provider_key, issuer_claim, and subject_claim
            return (
                OpenIdConnection.objects.select_related("user")
                .get(
                    provider_key=provider_key,
                    issuer_claim=issuer_claim,
                    subject_claim=subject_claim,
                )
                .user
            )
        except OpenIdConnection.DoesNotExist:
            return None
