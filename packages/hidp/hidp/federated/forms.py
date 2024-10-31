from django import forms
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils.translation import gettext_lazy as _

from ..accounts.forms import TermsOfServiceMixin
from .models import OpenIdConnection

UserModel = get_user_model()


class OIDCRegistrationForm(TermsOfServiceMixin, forms.ModelForm):
    """Create a user and OpenIDConnection from OIDC claims and user info."""

    template_name = "hidp/federated/forms/registration_form.html"

    # Fields
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

        # If the given name and family name are not provided, remove the fields.
        # They will be asked for during email verification.
        if not initial_data["first_name"] and not initial_data["last_name"]:
            self.fields.pop("first_name")
            self.fields.pop("last_name")
        else:
            self.fields["first_name"].required = True
            self.fields["last_name"].required = True

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

    template_name = "hidp/federated/forms/account_link_form.html"

    # Fields
    allow_link = forms.BooleanField(
        label=_("Yes, I want to link this account"),
        required=True,
        initial=True,
        widget=forms.HiddenInput(),
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


class OIDCAccountUnlinkForm(forms.Form):
    """Unlink an OpenIDConnection from a user."""

    template_name = "hidp/federated/forms/account_unlink_form.html"

    # Fields
    allow_unlink = forms.BooleanField(
        label=_("Yes, I want to unlink this account"),
        required=True,
        initial=True,
        widget=forms.HiddenInput(),
    )

    def __init__(self, *, user, provider_key, **kwargs):
        self.user = user
        self.provider_key = provider_key
        super().__init__(**kwargs)

    def clean(self):
        cleaned_data = super().clean()
        # Do not allow the user to unlink the only available login method.
        can_unlink = (
            self.user.has_usable_password()
            or self.user.openid_connections.exclude(
                provider_key=self.provider_key
            ).exists()
        )
        if not can_unlink:
            raise ValidationError(_("You cannot unlink your only way to sign in."))
        return cleaned_data
