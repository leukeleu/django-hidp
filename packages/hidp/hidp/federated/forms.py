from django import forms
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from ..accounts.forms import TermsOfServiceMixin
from .models import OpenIdConnection

UserModel = get_user_model()


class OIDCRegistrationForm(TermsOfServiceMixin, forms.ModelForm):
    """Create a user and OpenIDConnection from OIDC claims and user info."""

    agreed_to_tos = TermsOfServiceMixin.create_agreed_to_tos_field()

    def __init__(self, *, provider_key, claims, user_info, **kwargs):
        self.provider_key = provider_key
        self.claims = claims
        self.user_info = user_info
        # Populate the form using the OIDC claims and user info.
        oidc_data = claims | user_info
        initial_data = {
            "email": oidc_data.get("email"),
            "first_name": oidc_data.get("given_name"),
            "last_name": oidc_data.get("family_name"),
        } | kwargs.pop("initial", {})
        super().__init__(initial=initial_data, **kwargs)
        # Disable the email field to prevent the user from changing it.
        self.fields["email"].disabled = True

    class Meta:
        model = UserModel
        fields = [
            "email",
            "first_name",
            "last_name",
        ]

    @transaction.atomic
    def save(self, *, commit=True):
        user = super().save(commit=False)
        user.set_unusable_password()
        self.set_agreed_to_tos(user)
        user.connection = OpenIdConnection(
            user=user,
            provider_key=self.provider_key,
            issuer_claim=self.claims["iss"],
            subject_claim=self.claims["sub"],
        )
        if commit:
            user.save()
            user.connection.save()
        return user


class OIDCAccountLinkForm(forms.ModelForm):
    """Link an existing user to an OpenIDConnection."""

    allow_link = forms.BooleanField(
        label=_("Yes, I want to link this account."),
        required=True,
    )

    def __init__(self, *, user, provider_key, claims, **kwargs):
        self.user = user
        self.provider_key = provider_key
        self.claims = claims
        super().__init__(**kwargs)

    class Meta:
        model = OpenIdConnection
        fields = []

    @transaction.atomic
    def save(self, *, commit=True):
        self.instance = OpenIdConnection(
            user=self.user,
            provider_key=self.provider_key,
            issuer_claim=self.claims["iss"],
            subject_claim=self.claims["sub"],
        )
        if commit:
            self.instance.save()
        return self.instance
