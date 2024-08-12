from urllib.parse import urljoin

from django.core.mail import EmailMultiAlternatives
from django.template import loader

from hidp.accounts import email_verification


class BaseMailer:
    """
    Base class for sending templated emails.
    """

    subject_template_name = NotImplemented
    email_template_name = NotImplemented
    html_email_template_name = None

    def __init__(self, *, base_url):
        """
        Args:
            base_url:
                The base URL to use when generating links in the email.
        """
        self.base_url = base_url

    def get_context(self, extra_context=None):
        """
        Return a dictionary of context variables to use when rendering the
        email templates.
        """
        context = {
            "base_url": self.base_url,
        }
        return context | (extra_context or {})

    def get_recipients(self):
        """
        Return a list of email addresses to send the email to
        """
        raise NotImplementedError  # pragma: no cover

    def _get_subject(self, context):
        subject = loader.render_to_string(self.subject_template_name, context)
        # Email subject *must not* contain newlines
        return "".join(subject.splitlines())

    def _get_body(self, context):
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
    subject_template_name = "accounts/verification/email/verification_subject.txt"
    email_template_name = "accounts/verification/email/verification_body.txt"

    def __init__(self, user, *, base_url, post_verification_redirect=None):
        super().__init__(base_url=base_url)
        self.user = user
        self.post_verification_redirect = post_verification_redirect

    def get_context(self, extra_context=None):
        verification_url = urljoin(
            self.base_url,
            email_verification.get_verify_email_url(
                self.user,
                next_url=self.post_verification_redirect,
            ),
        )
        return super().get_context(
            {
                "user": self.user,
                "verification_url": verification_url,
            }
        )

    def get_recipients(self):
        return [self.user.email]
