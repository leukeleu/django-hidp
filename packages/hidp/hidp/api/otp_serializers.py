from rest_framework import serializers

from hidp.otp.forms import OTPSetupForm, VerifyStaticTokenForm, VerifyTOTPForm

from .serializers import FormSerializer


class OTPStatusSerializer(serializers.Serializer):
    configured = serializers.BooleanField()
    recovery_codes_remaining = serializers.IntegerField(allow_null=True)


class OTPSetupDetailsSerializer(serializers.Serializer):
    secret = serializers.CharField(help_text="The TOTP secret, base32 encoded.")
    config_url = serializers.CharField(help_text="The `otpauth://` URL of the device.")
    qr_code = serializers.CharField(help_text="The config URL as an SVG data URI.")
    recovery_codes = serializers.ListField(child=serializers.CharField())


class RecoveryCodesSerializer(serializers.Serializer):
    recovery_codes = serializers.ListField(child=serializers.CharField())


class OTPSetupSerializer(FormSerializer):
    form_class = OTPSetupForm

    otp_token = serializers.CharField(write_only=True)
    confirm_stored_backup_tokens = serializers.BooleanField(write_only=True)

    def get_form_kwargs(self, attrs):
        return {
            "user": self.request.user,
            "device": self.context["device"],
            "backup_device": self.context["backup_device"],
        }


class OTPTokenSerializer(FormSerializer):
    form_class = VerifyTOTPForm

    otp_token = serializers.CharField(write_only=True)

    def get_form_kwargs(self, attrs):
        return {"user": self.request.user}


class RecoveryCodeSerializer(FormSerializer):
    form_class = VerifyStaticTokenForm
    form_fields = {"recovery_code": ["otp_token"]}

    recovery_code = serializers.CharField(write_only=True)

    def get_form_kwargs(self, attrs):
        return {"user": self.request.user}
