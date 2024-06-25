from django.contrib.auth import models as auth_models
from django.db import models
from django.utils.translation import gettext_lazy as _

from ..compat.uuid7 import uuid7


class UserManager(auth_models.UserManager):
    """
    Custom user manager that uses email as the username field.
    """

    use_in_migrations = True

    def _create_user(self, username, email, password, **extra_fields):
        if not email:
            raise ValueError("User must have an email address")
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.clean()
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """
        Create a new user with the given email and password.

        Prefer using this method over instantiating the user model directly,
        as it ensures that the email address is normalized and the password is hashed.

        Automatically sets `is_staff` to `False` and `is_superuser` to `False`,
        unless explicitly set otherwise in `extra_fields`.
        """
        return super().create_user(
            username=email,
            email=email,
            password=password,
            **extra_fields,
        )

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create a new superuser with the given email and password.

        Automatically sets `is_staff` and `is_superuser` to `True`,
        unless explicitly set otherwise in `extra_fields`.
        """
        return super().create_superuser(
            username=email,
            email=email,
            password=password,
            **extra_fields,
        )


class BaseUser(auth_models.AbstractUser):
    """
    Extends the default Django user model, inheriting the following fields:

    * password (CharField):
      Hashed password
    * first_name (CharField, blank: True):
      Given name
    * last_name (CharField, blank: True):
      Family name
    * is_active (BooleanField, default: True):
      Whether the user is active (allowed to log in)
    * is_staff (BooleanField, default: False):
      Whether the user is a staff member (allowed to log into the admin site
    * is_superuser (BooleanField, default: False):
      Whether the user is a superuser (allowed to do anything)
    * groups (ManyToManyField):
      Groups the user belongs to
    * user_permissions (ManyToManyField):
      Permissions the user has
    * date_joined (DateTimeField, default: now):
      Date and time when the user was created
    * last_login (DateTimeField, default: None):
      Date and time when the user last logged in
      Populated by Django when the `django.contrib.auth.user_logged_in` signal is sent.

    Alters the default Django user model with the following modifications:

    * Primary key (id) is a UUID field populated with a version 7 UUID
    * The email field is case-insensitive, unique and required
    * The username field is removed in favor of the email field

    Adds the following fields:

    * email_verified (DateTimeField, default: None):
      Date and time when the email address was verified
    * last_modified (DateTimeField, auto_now: True):
      Date and time when the user was last modified

    Django's user model defines some convenience properties and methods:

    * `is_anonymous` (property):
      Always `False` (as opposed to always `True` for `AnonymousUser`)
    * `is_authenticated` (property):
      Always `True` (as opposed to always `False` for `AnonymousUser`)
    * `clean` (method):
      Normalizes the email address by lower-casing the domain part.
      Always call this method, after setting the email address, before saving the user.
    * `get_full_name` (method):
      Returns first and last name joined by a space.
    * `get_short_name` (method):
      Returns the first name.
    * `has_usable_password` (method):
      Returns `True` if the user has a password set and it doesn't begin with the
      unusable password prefix.
    """

    # Change the primary key to UUID
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    # Remove the username field
    username = None
    # Change the email field to be case-insensitive, unique and required
    email = models.EmailField(
        _("email address"), unique=True, db_collation="case_insensitive"
    )
    # Store the date when the email was verified
    email_verified = models.DateTimeField(
        _("email verified"), blank=True, null=True, editable=False
    )
    # Store the last modification date
    last_modified = models.DateTimeField(_("last modified"), auto_now=True)

    # Use the email field as the username field
    USERNAME_FIELD = "email"
    # Add names as required fields
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    class Meta:
        abstract = True
        verbose_name = _("user")
        verbose_name_plural = _("users")

    def set_password(self, raw_password):
        """
        Set the user's password field to the hashed value of the raw password.

        The user is **not** saved after setting the password.
        """
        super().set_password(raw_password)

    def set_unusable_password(self):
        """
        Set the user's password field to a value that will never be a valid hash.
        """
        super().set_unusable_password()

    def check_password(self, raw_password):
        """
        Check the raw password against the user's hashed password.

        Returns `True` if the password is correct, `False` otherwise.

        When the password is correct, but uses an outdated hashing algorithm,
        the password is upgraded to use the latest algorithm.

        Will save the user if the password is upgraded.
        """
        return super().check_password(raw_password)

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Email this user with the given subject and message.

        If `from_email` is not specified `settings.DEFAULT_FROM_EMAIL` is used.

        Additional keyword arguments are passed to the `send_mail` function as-is.
        """
        super().email_user(subject, message, from_email=from_email, **kwargs)


class User(BaseUser):
    pass
