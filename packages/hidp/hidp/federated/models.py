from django.conf import settings
from django.db import models
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

from ..compat.uuid7 import uuid7
from ..config import oidc_clients


class OpenIdConnectionQuerySet(models.QuerySet):
    def get_by_provider_and_claims(self, provider_key, *, issuer_claim, subject_claim):
        """
        Get an OpenID connection by provider key and claims.

        Prefetches the associated user along with the query.

        Args:
            provider_key (str): The provider key.
            issuer_claim (str): The issuer claim.
            subject_claim (str): The subject claim.

        Returns:
            OpenIdConnection: The OpenID connection if found, otherwise None.
        """
        return (
            self.select_related("user")
            .filter(
                provider_key=provider_key,
                issuer_claim=issuer_claim,
                subject_claim=subject_claim,
            )
            .first()
        )


class OpenIdConnection(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)

    # The associated user in HIdP
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="openid_connections",
    )

    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    last_modified = models.DateTimeField(_("last modified"), auto_now=True)

    # Short identifier for the identity provider (e.g. google, microsoft, etc.).
    provider_key = models.CharField(max_length=100)
    # The issuer of the identity token (Microsoft has tenant specific issuers).
    issuer_claim = models.CharField(max_length=255)
    # Unique identifier for the user at the identity provider (i.e. the "sub" claim)
    # Guaranteed to be unique together with the issuer_claim.
    subject_claim = models.CharField(max_length=255)

    # Manager
    objects = OpenIdConnectionQuerySet.as_manager()

    class Meta:
        # The sub (subject) and iss (issuer) Claims, used together,
        # are the only Claims that an RP can rely upon as a stable identifier
        # for the End-User, since the sub Claim MUST be locally unique and
        # never reassigned within the Issuer for a particular End-User [...].
        # Therefore, the only guaranteed unique identifier for a given End-User
        # is the combination of the iss Claim and the sub Claim.
        # https://openid.net/specs/openid-connect-basic-1_0.html#ClaimStability
        unique_together = (
            "provider_key",
            "issuer_claim",
            "subject_claim",
        )
        verbose_name = _("OpenID connection")
        verbose_name_plural = _("OpenID connections")

    def __str__(self):
        provider = oidc_clients.get_oidc_client_or_none(self.provider_key)
        provider_name = (
            provider.name
            if provider
            else format_lazy(
                _("Unknown provider: {provider_key}"),
                provider_key=self.provider_key,
            )
        )
        return f"{provider_name} ({self.subject_claim})"
