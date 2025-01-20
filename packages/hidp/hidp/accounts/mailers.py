from urllib.parse import urljoin

from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template import loader
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from . import email_verification, tokens
from .email_change import Recipient


class BaseMailer:
    """Base class for sending templated emails."""

    subject_template_name = NotImplemented
    email_template_name = NotImplemented
    html_email_template_name = None

    def __init__(self, *, base_url):
        """
        Initialize the mailer.

        Args:
            base_url:
                The base URL to use when generating links in the email.
        """
        self.base_url = base_url.rstrip("/")

    def get_context(self, extra_context=None):
        """Return a dictionary of context variables for the email templates."""
        context = {
            "base_url": self.base_url,
        }
        return context | (extra_context or {})

    def get_recipients(self):
        """Return a list of email addresses to send the email to."""
        raise NotImplementedError("Method get_recipients must be implemented")

    def _get_subject(self, context):
        if self.subject_template_name is NotImplemented:
            raise NotImplementedError("Attribute subject_template_name must be set")
        subject = loader.render_to_string(self.subject_template_name, context)
        # Email subject *must not* contain newlines
        return "".join(subject.splitlines())

    def _get_body(self, context):
        if self.email_template_name is NotImplemented:
            raise NotImplementedError("Attribute email_template_name must be set")
        return loader.render_to_string(self.email_template_name, context)

    def _add_optional_html_body(self, email_message, context):
        if self.html_email_template_name is not None:
            html_email = loader.render_to_string(self.html_email_template_name, context)
            email_message.attach_alternative(html_email, "text/html")

    def _get_message(self, from_email=None, extra_context=None):
        context = self.get_context(extra_context)
        subject = self._get_subject(context)
        body = self._get_body(context)

        email_message = EmailMultiAlternatives(
            subject, body, from_email, self.get_recipients()
        )
        self._add_optional_html_body(email_message, context)

        return email_message

    def send(
        self,
        *,
        from_email=None,
        extra_context=None,
    ):
        """
        Send a django.core.mail.EmailMultiAlternatives.

        Args:
            from_email:
                Email address to use as the sender of the email.
                Optional, uses the `DEFAULT_FROM_EMAIL` setting if not provided.
            extra_context:
                A dictionary of extra context variables to use when rendering the
                email templates (optional).
        """
        self._get_message(from_email, extra_context).send()


class EmailVerificationMailer(BaseMailer):
    subject_template_name = "hidp/accounts/verification/email/verification_subject.txt"
    email_template_name = "hidp/accounts/verification/email/verification_body.txt"
    html_email_template_name = "hidp/accounts/verification/email/verification_body.html"

    def __init__(self, user, *, base_url, post_verification_redirect=None):
        super().__init__(base_url=base_url)
        self.user = user
        self.post_verification_redirect = post_verification_redirect

    def get_verification_url(self):
        return urljoin(
            self.base_url,
            email_verification.get_verify_email_url(
                self.user,
                next_url=self.post_verification_redirect,
            ),
        )

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "user": self.user,
                "verification_url": self.get_verification_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [self.user.email]


class AccountExistsMailer(BaseMailer):
    subject_template_name = (
        "hidp/accounts/verification/email/account_exists_subject.txt"
    )
    email_template_name = "hidp/accounts/verification/email/account_exists_body.txt"
    html_email_template_name = (
        "hidp/accounts/verification/email/account_exists_body.html"
    )

    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_password_reset_url(self):
        return urljoin(self.base_url, reverse("hidp_accounts:password_reset_request"))

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "user": self.user,
                "password_reset_url": self.get_password_reset_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [self.user.email]


class PasswordResetRequestMailer(BaseMailer):
    subject_template_name = "hidp/accounts/recovery/email/password_reset_subject.txt"
    email_template_name = "hidp/accounts/recovery/email/password_reset_body.txt"
    html_email_template_name = "hidp/accounts/recovery/email/password_reset_body.html"
    token_generator = default_token_generator

    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_password_reset_url(self):
        """
        Return the URL to the password reset page for the given user.

        Returns:
            An absolute URL to the password reset page for the given user.
        """
        return urljoin(
            self.base_url,
            reverse(
                "hidp_accounts:password_reset",
                kwargs={
                    "uidb64": urlsafe_base64_encode(force_bytes(self.user.pk)),
                    "token": self.token_generator.make_token(self.user),
                },
            ),
        )

    def get_context(self, extra_context=None):
        email_field_name = self.user.__class__.get_email_field_name()
        user_email = getattr(self.user, email_field_name)
        return super().get_context(
            {
                "email": user_email,
                "user": self.user,
                "password_reset_url": self.get_password_reset_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [self.user.email]


class SetPasswordMailer(BaseMailer):
    subject_template_name = "hidp/accounts/recovery/email/set_password_subject.txt"
    email_template_name = "hidp/accounts/recovery/email/set_password_body.txt"
    html_email_template_name = "hidp/accounts/recovery/email/set_password_body.html"

    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_set_password_url(self):
        return urljoin(self.base_url, reverse("hidp_account_management:set_password"))

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "user": self.user,
                "set_password_url": self.get_set_password_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [self.user.email]


class PasswordChangedMailer(BaseMailer):
    subject_template_name = (
        "hidp/accounts/management/email/password_changed_subject.txt"
    )
    email_template_name = "hidp/accounts/management/email/password_changed_body.txt"
    html_email_template_name = (
        "hidp/accounts/management/email/password_changed_body.html"
    )

    def __init__(self, user, *, base_url):
        super().__init__(base_url=base_url)
        self.user = user

    def get_password_reset_url(self):
        return urljoin(self.base_url, reverse("hidp_accounts:password_reset_request"))

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "user": self.user,
                "password_reset_url": self.get_password_reset_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [self.user.email]


class EmailChangeRequestMailer(BaseMailer):
    subject_template_name = "hidp/accounts/management/email/email_change_subject.txt"
    email_template_name = "hidp/accounts/management/email/email_change_body.txt"
    html_email_template_name = "hidp/accounts/management/email/email_change_body.html"

    def __init__(self, user, *, base_url, email_change_request, recipient):
        super().__init__(base_url=base_url)
        self.user = user
        self.email_change_request = email_change_request
        self.recipient = recipient

    def get_confirmation_url(self):
        return urljoin(
            self.base_url,
            reverse(
                "hidp_account_management:email_change_confirm",
                kwargs={
                    "token": (
                        tokens.email_change_token_generator.make_token(
                            str(self.email_change_request.pk), self.recipient
                        )
                    )
                },
            ),
        )

    def get_cancel_url(self):
        return urljoin(
            self.base_url,
            reverse("hidp_account_management:email_change_cancel"),
        )

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "user": self.user,
                "recipient": self.recipient,
                "current_email": self.email_change_request.current_email,
                "proposed_email": self.email_change_request.proposed_email,
                "confirmation_url": self.get_confirmation_url(),
                "cancel_url": self.get_cancel_url(),
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        match self.recipient:
            case Recipient.CURRENT_EMAIL:
                return [self.email_change_request.current_email]
            case Recipient.PROPOSED_EMAIL:
                return [self.email_change_request.proposed_email]
            case _:
                raise ValueError(f"Invalid recipient: {self.recipient!r}")


class ProposedEmailExistsMailer(EmailChangeRequestMailer):
    subject_template_name = (
        "hidp/accounts/management/email/proposed_email_exists_subject.txt"
    )
    email_template_name = (
        "hidp/accounts/management/email/proposed_email_exists_body.txt"
    )
    html_email_template_name = (
        "hidp/accounts/management/email/proposed_email_exists_body.html"
    )

    def get_context(self, extra_context=None):
        return {
            "current_email": self.email_change_request.current_email,
            "proposed_email": self.email_change_request.proposed_email,
            "cancel_url": self.get_cancel_url(),
        }


class EmailChangedMailer(BaseMailer):
    subject_template_name = "hidp/accounts/management/email/email_changed_subject.txt"
    email_template_name = "hidp/accounts/management/email/email_changed_body.txt"
    html_email_template_name = "hidp/accounts/management/email/email_changed_body.html"

    def __init__(self, user, *, email_change_request, base_url):
        super().__init__(base_url=base_url)
        self.user = user
        self.email_change_request = email_change_request

    def get_context(self, extra_context=None):
        return super().get_context(
            {
                "current_email": self.email_change_request.current_email,
                "proposed_email": self.email_change_request.proposed_email,
            }
            | (extra_context or {})
        )

    def get_recipients(self):
        return [
            self.email_change_request.current_email,
            self.email_change_request.proposed_email,
        ]
