from django.contrib.auth import forms as auth_forms


class AuthenticationForm(auth_forms.AuthenticationForm):
    """
    Default AuthenticationForm, allows user to login with username and password.

    The username field is mapped to User.USERNAME_FIELD, this allows the
    user model to be change the username field to an alternative field,
    for example email.
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
