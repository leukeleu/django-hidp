from rest_framework import serializers

from django.utils.translation import gettext_lazy as _

from hidp.config import oidc_clients
from hidp.federated import flows
from hidp.federated.forms import OIDCAccountLinkForm, OIDCRegistrationForm

from .serializers import FormSerializer, NextSerializerMixin


class OIDCProviderSerializer(serializers.Serializer):
    key = serializers.CharField(source="provider_key")
    name = serializers.CharField()


class OIDCConnectionSerializer(OIDCProviderSerializer):
    linked = serializers.BooleanField()
    can_unlink = serializers.BooleanField()


class OIDCAuthenticateSerializer(NextSerializerMixin):
    reauthenticate = serializers.BooleanField(default=False, write_only=True)


class OIDCTokenSerializerMixin(serializers.Serializer):
    """The `token` of a step of logging in with a provider, which has its data."""

    token_generator = NotImplemented

    token = serializers.CharField(write_only=True)

    def validate_token(self, value):
        self.token_data = flows.get_token_data(
            self.context["request"], value, token_generator=self.token_generator
        )
        if self.token_data is None:
            raise serializers.ValidationError(
                _("The login has expired. Please log in again.")
            )
        return value

    @property
    def provider(self):
        return oidc_clients.get_oidc_client(self.token_data["provider_key"])


class OIDCRegistrationTokenSerializer(OIDCTokenSerializerMixin):
    token_generator = flows.registration_token_generator


class OIDCRegistrationSerializer(
    NextSerializerMixin, OIDCRegistrationTokenSerializer, FormSerializer
):
    """
    Create the account of a first login with a provider.

    The names default to the ones the provider sent. Without those, they are asked
    for when the email address is verified.
    """

    form_class = OIDCRegistrationForm
    non_form_fields = ("next", "token")

    agreed_to_tos = serializers.BooleanField(write_only=True)
    first_name = serializers.CharField(write_only=True, required=False)
    last_name = serializers.CharField(write_only=True, required=False)

    def get_form_data(self, attrs):
        oidc_data = self.token_data["claims"] | self.token_data["user_info"]
        return {
            "first_name": oidc_data.get("given_name"),
            "last_name": oidc_data.get("family_name"),
        } | super().get_form_data(attrs)

    def get_form_kwargs(self, attrs):
        return {
            "provider_key": self.token_data["provider_key"],
            "claims": self.token_data["claims"],
            "user_info": self.token_data["user_info"],
        }


class OIDCLinkTokenSerializer(OIDCTokenSerializerMixin):
    token_generator = flows.link_token_generator


class OIDCLinkSerializer(OIDCLinkTokenSerializer, FormSerializer):
    """Link the account of the provider to the logged-in user."""

    form_class = OIDCAccountLinkForm
    non_form_fields = ("token",)

    def get_form_data(self, attrs):  # noqa: PLR6301 (no-self-use)
        # Posting the token is the consent the HTML form asks for.
        return {"allow_link": True}

    def get_form_kwargs(self, attrs):
        return {
            "user": self.context["request"].user,
            "provider_key": self.token_data["provider_key"],
            "claims": self.token_data["claims"],
        }
