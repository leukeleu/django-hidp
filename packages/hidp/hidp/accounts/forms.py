from django import forms
from django.contrib.auth import forms as auth_forms
from django.contrib.auth import get_user_model
from django.urls import reverse_lazy
from django.utils import timezone
from django.utils.safestring import mark_safe
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _

UserModel = get_user_model()


class TermsOfServiceMixin:
    @staticmethod
    def create_agreed_to_tos_field():
        label = mark_safe(  # noqa: S308 (safe string, no user input)
            format_lazy(
                _('I have read and accept the <a href="{url}">Terms of Service</a>.'),
                url=reverse_lazy("hidp_accounts:tos"),
            )
        )
        return forms.BooleanField(label=label, required=True)

    def set_agreed_to_tos(self, user):
        """Populate the `agreed_to_tos` field, if the user agreed."""
        if self.cleaned_data.get("agreed_to_tos", False):
            # Ensure the user has agreed to the terms of service.
            # Subclasses may remove the field, or make it optional.
            user.agreed_to_tos = timezone.now()


class UserCreationForm(TermsOfServiceMixin, auth_forms.BaseUserCreationForm):
    """
    Default UserCreationForm, allows user to register with username and password.

    The user **must** agree to the terms of service to register.

    The username field is mapped to `User.USERNAME_FIELD`. This makes it possible
    to change the username field to a different one, such as an email address.

    The user is asked to enter the password twice to avoid typos.
    The password is validated using the validators configured in
    `settings.AUTH_PASSWORD_VALIDATORS`.
    """

    agreed_to_tos = TermsOfServiceMixin.create_agreed_to_tos_field()
    # Remove the option to create an account with an unusable password.
    usable_password = None

    class Meta:
        model = UserModel
        fields = (UserModel.USERNAME_FIELD,)

    def _get_validation_exclusions(self):
        # Exclude email from model validation (unique constraint),
        # This will make the form valid even if the email is already in use.
        # This results in a IntegrityError when saving the user, which
        # must be handled by the view, to prevent user enumeration attacks.
        return {"email", *super()._get_validation_exclusions()}

    def save(self, *, commit=True):
        user = super().save(commit=False)
        self.set_agreed_to_tos(user)
        if commit:
            user.save()
        return user


class EmailVerificationForm(forms.Form):
    """Store the date and time when the user verified their email address."""

    def __init__(self, user, *args, **kwargs):
        """
        Initialize the form with the given `user`.

        The `user` is stored in an instance variable, to allow all
        form methods to access the user.
        """
        super().__init__(*args, **kwargs)
        self.user = user

    def save(self, *, commit=True):
        """
        Mark the user as verified.

        Args:
            commit:
                Whether to save the user to the database after
                marking the user as verified.

        Returns:
            The user with the email address verified.
        """
        if commit:
            self.user.email_verified = timezone.now()
            self.user.save(update_fields=["email_verified"])
        return self.user


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


class PasswordResetRequestForm(forms.Form):
    """Start the password reset process by requesting a password reset email."""

    email = forms.EmailField(
        label=_("Email"),
        max_length=254,
        widget=forms.EmailInput(attrs={"autocomplete": "email"}),
    )

    def get_user(self):
        """
        Given an email, return the user who should receive a reset.

        Returns None if no user is found, or the user is not allowed
        to reset their password (e.g. inactive, no password).
        """
        user = UserModel.objects.filter(
            email__iexact=self.cleaned_data["email"], is_active=True
        ).first()
        if user and user.has_usable_password():
            return user
        return None


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


class RateLimitedAuthenticationForm(AuthenticationForm):
    """
    Authentication form that is used when a user is rate limited.

    This form includes a simple "I am not a robot" checkbox to demonstrate
    how additional protection can be added to an authentication form.

    It is recommended to replace this form with a more robust implementation
    that provides stronger protection against automated attacks.
    """

    i_am_not_a_robot = forms.BooleanField(
        label=_("I am not a robot"),
        required=True,
        error_messages={
            "required": _("Please confirm that you are not a robot."),
        },
    )


class EditUserForm(forms.ModelForm):
    class Meta:
        model = UserModel
        fields = ("first_name", "last_name")
