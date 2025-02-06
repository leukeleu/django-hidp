from django.urls import reverse

from hidp.accounts.mailers import BaseMailer


class BaseOTPUserMailer(BaseMailer):
    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_recipients(self):
        return [self.user.email]


class OTPConfiguredMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/configured_subject.txt"
    email_template_name = "hidp/otp/email/configured_body.txt"
    html_email_template_name = "hidp/otp/email/configured_body.html"

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "otp_management_url": self.base_url + reverse("hidp_otp_management:manage"),
            }
            | (extra_context or {})
        )


class OTPDisabledMailer(BaseOTPUserMailer):
    subject_template_name = "hidp/otp/email/disabled_subject.txt"
    email_template_name = "hidp/otp/email/disabled_body.txt"
    html_email_template_name = "hidp/otp/email/disabled_body.html"

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "otp_management_url": self.base_url + reverse("hidp_otp_management:manage"),
            }
            | (extra_context or {})
        )
