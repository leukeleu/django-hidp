from urllib.parse import urljoin

from django import forms
from django.contrib.auth import forms as auth_forms
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils.safestring import mark_safe
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

UserModel = get_user_model()


class UserCreationForm(auth_forms.UserCreationForm):
    """
    Default UserCreationForm, allows user to register with username and password.
    The user **must** agree to the terms of service to register.

    The username field is mapped to `User.USERNAME_FIELD`. This makes it possible
    to change the username field to a different one, such as an email address.

    The user is asked to enter the password twice to avoid typos.
    The password is validated using the validators configured in
    `settings.AUTH_PASSWORD_VALIDATORS`.

    Username is validated to ensure it is unique (in a case-insensitive way).
    """

    agreed_to_tos = forms.BooleanField(
        label=mark_safe(  # noqa: S308 (safe string, no user input)
            format_lazy(
                _('I have read and accept the <a href="{url}">Terms of Service</a>.'),
                url=reverse_lazy("hidp_accounts:tos"),
            )
        ),
        required=True,
    )
    # Remove the option to create an account with an unusable password.
    usable_password = None

    class Meta(auth_forms.UserCreationForm.Meta):
        model = UserModel
        fields = (UserModel.USERNAME_FIELD,)

    def save(self, *, commit=True):
        user = super().save(commit=commit)
        if not self.cleaned_data.get("agreed_to_tos", False):
            # Handle the case where agreed_to_tos is removed,
            # or is made optional, by a subclass.
            return user

        user.agreed_to_tos = timezone.now()
        if commit:
            user.save(update_fields=["agreed_to_tos"])
        return user


class AuthenticationForm(auth_forms.AuthenticationForm):
    """
    Default AuthenticationForm, allows user to log in with username and password.

    The username field is mapped to `User.USERNAME_FIELD`. This makes it possible
    to change the username field to a different one, such as an email address.
    """

    def __init__(self, request=None, *args, **kwargs):
        """
        Initialize the form with the given `request`.

        The `request` is stored in an instance variable, to allow all
        form methods to access the request.
        """
        super().__init__(request, *args, **kwargs)

    def is_valid(self):
        """
        Validate the username and password.

        Returns `True` if the credentials are valid and the user
        is allowed to log in, otherwise `False`.

        Validation errors are stored in the form's `errors` attribute.
        """
        return super().is_valid()

    def get_user(self):
        """
        Return the user authenticated by the form (after calling `is_valid`).

        Returns `None` if no user was authenticated.
        """
        return super().get_user()

    def get_invalid_login_error(self):
        """
        Hook to alter the error message when authentication fails.

        The default implementation returns a fixed message, regardless of
        the credentials provided by the user. This message is parameterized
        to use the name of the username field, as defined by the user model.

        To customize the error message, subclass this form and override
        `AuthenticationForm.messages['invalid_login']`.
        """
        return super().get_invalid_login_error()

    def confirm_login_allowed(self, user):
        """
        Hook to perform additional checks on the user, before logging them in.

        The default implementation checks if the user is active, and raises
        a `ValidationError` if the user is not active.

        To change the message raised when a user is active, subclass this form
        and override `AuthenticationForm.messages['inactive']`.

        Note:

        The default backend (`django.contrib.auth.backends.ModelBackend`) does
        not authenticate inactive users, and will not call this method for
        inactive users.

        To allow inactive users to authenticate, but prevent them from
        logging in, set `settings.AUTHENTICATION_BACKENDS` to
        `django.contrib.auth.backends.AllowAllUsersModelBackend`.
        """
        return super().confirm_login_allowed(user)


class PasswordResetRequestForm(auth_forms.PasswordResetForm):
    """
    Start the password reset process for a user, by requesting a
    password reset email.

    The user is asked to enter their email address, and a password reset email
    is sent to the user. The email contains a link to a page that allows the
    user to enter a new password.

    Attributes:
        subject_template_name:
            Template to use for the email subject.
        email_template_name:
            Template to use for the email body.
        html_email_template_name:
            The name of the template to use for the HTML email body.
            Optional, defaults to `None`.
        password_reset_token_generator:
            Token generator to use for the password reset token.
            Defaults to `django.contrib.auth.tokens.default_token_generator`.
    """

    subject_template_name = "accounts/recovery/email/password_reset_subject.txt"
    email_template_name = "accounts/recovery/email/password_reset_body.txt"
    html_email_template_name = None
    password_reset_token_generator = default_token_generator

    def get_users(self, email):
        """
        Return all **active** users with the given email address (case-insensitive),
        that have a usable password. Should be one user at most, if the correct
        user model is used.

        Inactive users, and users with unusable passwords, are not allowed to
        perform a password reset.

        Args:
            email:
                The email address to use for the user lookup.

        Returns:
            A generator that yields all active users, that have a usable password,
            with the given email address (case-insensitive).
        """
        return super().get_users(email)

    def send_mail(self, *, to_email, context, from_email=None):
        """
        Send a password reset email to the user.

        Called by the `save` method to send the email to the user.
        The `save` method is also responsible for providing the context data
        required to build a functional password reset email.

        Args:
            to_email:
                The email address to send the email to.
            context:
                Context data for email templates, used for the
                subject and body templates.
            from_email:
                Email address to use as the sender of the email.
                Optional, uses the `DEFAULT_FROM_EMAIL` setting if not provided.

        """
        super().send_mail(
            from_email=from_email,
            to_email=to_email,
            subject_template_name=self.subject_template_name,
            email_template_name=self.email_template_name,
            html_email_template_name=self.html_email_template_name,
            context=context,
        )

    def get_password_reset_token(self, user):
        """
        Return the password reset token for the given user.

        The token is used to create a link to the password reset page.

        Args:
            user:
                User that requested the password reset.

        Returns:
            A token for the password reset page.
        """
        return self.password_reset_token_generator.make_token(user)

    def get_password_reset_url(self, *, user, base_url, password_reset_view):
        """
        Return the URL to the password reset page for the given user.

        Args:
            user:
                User that requested the password reset.
            base_url:
                Used to make an absolute URL to the password reset page.
                Use `request.build_absolute_uri("/")` to populate this value if the
                request object is available.
            password_reset_view:
                Name that reverses to the password reset view.

        Returns:
            An absolute URL to the password reset page for the given user.
        """
        return urljoin(
            base_url,
            reverse(
                password_reset_view,
                kwargs={
                    "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
                    "token": self.get_password_reset_token(user),
                },
            ),
        )

    def get_email_template_context(
        self,
        *,
        user,
        base_url,
        password_reset_view,
        extra_email_context=None,
    ):
        """
        Return the context data for the password reset email.

        Args:
            user:
                User that requested the password reset.
            base_url:
                Used to make an absolute URL to the password reset page in the email.
                Use `request.build_absolute_uri("/")` to populate this value if the
                request object is available.
            password_reset_view:
                Name that reverses to the password reset view.
            extra_email_context:
                Extra context data to add to the email context.

        Returns:
            A dictionary with the following keys:

            * `email`: The email address of the user.
            * `user`: The user that requested the password reset.
            * `password_reset_url`: The URL to the password reset page.
            * Any additional data present in `extra_email_context`.
        """
        email_field_name = UserModel.get_email_field_name()
        user_email = getattr(user, email_field_name)
        return {
            "email": user_email,
            "user": user,
            "password_reset_url": self.get_password_reset_url(
                user=user, base_url=base_url, password_reset_view=password_reset_view
            ),
        } | (extra_email_context or {})

    def save(
        self,
        *,
        base_url,
        password_reset_view,
        from_email=None,
        extra_email_context=None,
    ):
        """
        Each user that matches the entered email address is sent a password
        reset email.

        Args:
            from_email:
                Email address to use as the sender of the email.
                Optional, uses the `DEFAULT_FROM_EMAIL` setting if not provided.
            base_url:
                Used to make an absolute URL to the password reset page in the email.
                Use `request.build_absolute_uri("/")` to populate this value if the
                request object is available.
            password_reset_view:
                Name that reverses to the password reset view.
            extra_email_context:
                Extra context data to add to the email context.
        """
        for user in self.get_users(self.cleaned_data["email"]):
            context = self.get_email_template_context(
                user=user,
                base_url=base_url,
                password_reset_view=password_reset_view,
                extra_email_context=extra_email_context,
            )
            self.send_mail(
                to_email=context["email"],
                context=context,
                from_email=from_email,
            )


class PasswordResetForm(auth_forms.SetPasswordForm):
    """
    Allows the user to set a new password without entering the old password.

    The user is asked to enter a new password twice to avoid typos.
    The password is validated using the validators configured in
    `settings.AUTH_PASSWORD_VALIDATORS`.
    """

    def __init__(self, user, *args, **kwargs):
        """
        Initialize the form with the given `user`.

        The `user` is stored in an instance variable, to allow all
        form methods to access the user.
        """
        super().__init__(user, *args, **kwargs)

    def save(self, *, commit=True):
        """
        Save the new password for the user.

        Args:
            commit:
                Whether to save the user to the database after
                setting the password.

        Returns:
            The user with the new password set.
        """
        return super().save(commit=commit)
