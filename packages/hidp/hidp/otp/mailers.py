from django_otp.plugins.otp_static.models import StaticDevice

from django.urls import reverse

from hidp.accounts.mailers import BaseMailer
from hidp.otp.devices import get_device_for_user


class BaseOTPUserMailer(BaseMailer):
    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_recipients(self):
        return [self.user.email]

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "otp_management_url": self.base_url
                + reverse("hidp_otp_management:manage")
            }
            | (extra_context or {})
        )


class OTPConfiguredMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/configured_subject.txt"
    email_template_name = "hidp/otp/email/configured_body.txt"
    html_email_template_name = "hidp/otp/email/configured_body.html"


class OTPDisabledMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/disabled_subject.txt"
    email_template_name = "hidp/otp/email/disabled_body.txt"
    html_email_template_name = "hidp/otp/email/disabled_body.html"


class RecoveryCodeUsedMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/recovery_code_used_subject.txt"
    email_template_name = "hidp/otp/email/recovery_code_used_body.txt"
    html_email_template_name = "hidp/otp/email/recovery_code_used_body.html"

    def get_context(self, extra_context=None):
        device = get_device_for_user(self.user, StaticDevice)

        return super().get_context(
            {
                "recovery_codes_count": device.token_set.count(),
            }
            | (extra_context or {})
        )


class RecoveryCodesRegeneratedMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/recovery_codes_regenerated_subject.txt"
    email_template_name = "hidp/otp/email/recovery_codes_regenerated_body.txt"
    html_email_template_name = "hidp/otp/email/recovery_codes_regenerated_body.html"
