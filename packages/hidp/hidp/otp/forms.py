from django_otp import verify_token
from django_otp.forms import OTPAuthenticationFormMixin
from django_otp.forms import OTPTokenForm as DjangoOTPTokenForm

from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _


class OTPTokenForm(DjangoOTPTokenForm):
    otp_challenge = None  # don't require OTP challenge for OTP token form


class OTPSetupForm(forms.Form):
    otp_token = forms.CharField(
        label=_("Verify the code from the app"),
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
            }
        ),
    )
    confirm_stored_backup_tokens = forms.BooleanField(
        required=True,
        label=_("I have stored my backup codes in a safe place"),
        help_text=_(
            "You can use these codes to log in if you lose access to your device"
        ),
    )

    def __init__(self, *args, user, device, backup_device, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.device = device
        self.backup_device = backup_device

    def clean_otp_token(self):
        token = self.cleaned_data["otp_token"]
        if not verify_token(self.user, self.device.persistent_id, token):
            raise ValidationError(
                _("Enter a valid one-time password token."), code="token_invalid"
            )
        return token

    def save(self):
        # Mark the devices as confirmed
        self.device.confirmed = True
        self.device.save(update_fields=["confirmed"])
        self.backup_device.confirmed = True
        self.backup_device.save(update_fields=["confirmed"])


class OTPVerifyForm(OTPAuthenticationFormMixin, forms.Form):
    """
    A form used to verify an OTP token.

    This form is used to verify an OTP token entered by the user. It will verify the
    token against any confirmed OTP devices the user has.
    """

    otp_token = forms.CharField(
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code"})
    )

    def __init__(self, user, request=None, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.user = user

    def clean(self):
        super().clean()

        self.clean_otp(self.user)

        return self.cleaned_data
