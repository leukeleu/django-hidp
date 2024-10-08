from django.conf import settings
from django.contrib.auth import models as auth_models
from django.db import models
from django.db.models import functions
from django.utils.translation import gettext_lazy as _

from ..compat.uuid7 import uuid7


class UserQuerySet(models.QuerySet):
    def email_verified(self):
        """
        Only include users that have verified their email address.

        Returns:
            ``QuerySet``: Users that have verified their email address.
        """
        return self.exclude(email_verified__isnull=True)

    def email_unverified(self):
        """
        Only include users that have not verified their email address.

        Returns:
            ``QuerySet``: Users that have not verified their email address.
        """
        return self.filter(email_verified__isnull=True)


class UserManager(auth_models.UserManager.from_queryset(UserQuerySet)):
    """Custom user manager that uses email as the username field."""

    use_in_migrations = True

    def _create_user(self, username, email, password, **extra_fields):
        if not email:
            raise ValueError("User must have an email address")
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        """
        Create a new user with the given email and password.

        Prefer using this method over instantiating the user model directly,
        as it ensures that the email address is normalized and the password is hashed.

        Automatically sets ``is_staff`` to ``False`` and ``is_superuser`` to ``False``,
        unless explicitly set otherwise in ``extra_fields``.

        Args:
            email (``str``): The email address of the user.
            password (``str``, `optional`): The password of the user.
            **extra_fields: Additional fields to set on the user.

        Returns:
            ``User``: The newly created user.
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

        Automatically sets ``is_staff`` and ``is_superuser`` to ``True``,
        unless explicitly set otherwise in ``extra_fields``.

        Args:
            email (``str``): The email address of the user.
            password (``str``, `optional`): The password of the user.
            **extra_fields: Additional fields to set on the user.

        Returns:
            ``User``: The newly created superuser.
        """
        return super().create_superuser(
            username=email,
            email=email,
            password=password,
            **extra_fields,
        )


class BaseUser(auth_models.AbstractUser):
    """
    Abstract base class that extends Django's default user model.

    Attributes:
        password (``CharField``):
            Hashed password.

        first_name (``CharField``):
            Given name, `optional`

        last_name (``CharField``):
            Family name, `optional`

        is_active (``BooleanField``):
            Whether the user is active (allowed to log in).

            Defaults to ``True``.

        is_staff (``BooleanField``):
            Whether the user is a staff member (allowed to log into the admin site).

            This field is used exclusively by Django's permissions system and
            has no special meaning in HIdP. It is recommended to avoid direct use
            of this field in your application code. Instead, rely on the permissions
            features provided by Django.

            Defaults to ``False``.

        is_superuser (``BooleanField``):
            Whether the user is a superuser (allowed to do anything).

            This field has no additional meaning in HIdP. It is recommended to avoid
            direct use of this field in your application code. Instead, rely on Django's
            group features to assign specific permissions groups of users.

            Defaults to ``False``.

        groups (``ManyToManyField``):
            Groups the user belongs to

        user_permissions (``ManyToManyField``):
            Permissions the user has

        date_joined (``DateTimeField``):
            Date and time when the user was created.

            Defaults to the current date and time.

        last_login (``DateTimeField``):
            Date and time when the user last logged in
            Populated by Django when the ``django.contrib.auth.user_logged_in`` signal
            is sent.

            Defaults to ``None``.

    .. rubric:: Alters the default Django user model with the following modifications
        :heading-level: 3

    Attributes:
        id (``UUIDField``):
            Primary key, a version 7 UUID.

            Altered:
                Was ``int`` in the default Django user model.

        email (``EmailField``):
            Email address, case-insensitive, unique and required.

            Altered:
                Was case-sensitive, not unique and optional in the default Django
                user model.

        username (``None``):
            Altered:
                The username field is removed in favor of the email field

    .. rubric:: Adds the following attributes
        :heading-level: 3

    Attributes:
        email_verified (``DateTimeField``):
            Date and time when the email address was verified.

            Defaults to ``None``.

        agreed_to_tos (``DateTimeField``):
            Date and time when the user agreed to the terms of service.

            Defaults to ``None``

        last_modified (``DateTimeField``):
            Date and time when the user was last modified. Populated by Django when
            the user is saved.

            Defaults to the current date and time.
    """

    # Change the primary key to UUID
    id = models.UUIDField(primary_key=True, default=uuid7, editable=False)
    # Remove the username field
    username = None
    email = models.EmailField(_("email address"), unique=True)
    # Store the date when the email was verified
    email_verified = models.DateTimeField(
        _("email verified"), blank=True, null=True, editable=False
    )
    # Store the last modification date
    last_modified = models.DateTimeField(_("last modified"), auto_now=True)
    # Store when the user agreed to the terms of service
    agreed_to_tos = models.DateTimeField(
        _("agreed to terms of service"),
        blank=True,
        null=True,
    )

    # Use the email field as the username field
    USERNAME_FIELD = "email"
    # Add names as required fields
    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    class Meta:
        abstract = True
        verbose_name = _("user")
        verbose_name_plural = _("users")
        constraints = [
            models.UniqueConstraint(
                functions.Lower("email"),
                name="unique_lower_email",
            )
        ]

    @property
    def is_anonymous(self):
        """
        Helper property to find out if user is anonymous or authenticated.

        ``bool``: Always ``False``. As opposed to always ``True`` for ``AnonymousUser``.
        """
        return super().is_anonymous

    @property
    def is_authenticated(self):
        """
        Helper property to find out if user is anonymous or authenticated.

        ``bool``: Always ``True``. As opposed to always ``False`` for ``AnonymousUser``.
        """
        return super().is_authenticated

    def check_password(self, raw_password):
        """
        Check the raw password against the user's hashed password.

        When the password is correct, but uses an outdated hashing algorithm,
        the password is upgraded to use the latest algorithm.

        Will save the user if the password is upgraded.

        Args:
            raw_password (``str``): The raw password to be checked.

        Returns:
            ``True`` if the password is correct, ``False`` otherwise.

        """
        return super().check_password(raw_password)

    def clean(self):
        """
        Normalize the email address by lower-casing the domain part.

        Automatically called before saving the user.
        """
        super().clean()

    def email_user(self, subject, message, from_email=None, **kwargs):  # noqa: D417
        """
        Email this user with the given subject and message.

        If ``from_email`` is not specified ``settings.DEFAULT_FROM_EMAIL`` is used.

        Additional keyword arguments are passed to the `send_mail` function as-is.

        Args:
            subject (``str``): The subject of the email.
            message (``str``): The message of the email.
            from_email (``str``, `optional`): The sender's email address.
        """
        super().email_user(subject, message, from_email=from_email, **kwargs)

    def get_full_name(self):
        """
        Return the first name and the last name, separated by a space.

        Returns:
            ``str``: The full name of the user.
        """
        return super().get_full_name()

    def get_short_name(self):
        """
        Return the first name.

        Returns:
            ``str``: The first name of the user.
        """
        return super().get_short_name()

    def has_usable_password(self):
        """
        Check if the user has a usable password.

        Returns:
            ``bool``: ``True`` if the user has a password set and it doesn't begin with
            the unusable password prefix.
        """
        return super().has_usable_password()

    def save(self, *args, update_fields=None, **kwargs):
        """
        Save the user to the database.

        Altered:
            Always normalizes the email address before saving.
        """
        self.clean()  # Always normalize the email address
        super().save(*args, update_fields=update_fields, **kwargs)

    def set_password(self, raw_password):
        """
        Set the user's password field to the hashed value of the raw password.

        The user is **not** saved after setting the password.

        Args:
            raw_password (``str``): The raw password to be hashed.
        """
        super().set_password(raw_password)

    def set_unusable_password(self):
        """Set the user's password field to a value that will never be a valid hash."""
        super().set_unusable_password()


class EmailChangeRequest(models.Model):
    """
    A user's request to change their email and it's confirmation state.

    Attributes:
        uuid (``UUIDField``):
            Primary key, a version 7 UUID.

        user (``OneToOneField``):
            The user that requested the email change.

        proposed_email (``EmailField``):
            The email address the user wants to change to.

        confirmed_by_proposed_email (``BooleanField``):
            Whether the email change has been confirmed by the proposed email address.

            Defaults to ``False``.

        confirmed_by_current_email (``BooleanField``):
            Whether the email change has been confirmed by the current email address.

            Defaults to ``False``.

        created (``DateTimeField``):
            Date and time when the email change request was created.

        modified (``DateTimeField``):
            Date and time when the email change request was last modified.
    """

    id = models.UUIDField(default=uuid7, editable=False, primary_key=True)
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="email_change_request",
        verbose_name=_("user"),
    )
    current_email = models.EmailField(_("current email address"))
    proposed_email = models.EmailField(_("proposed email address"))
    confirmed_by_proposed_email = models.BooleanField(
        _("confirmed by proposed email"),
        default=False,
    )
    confirmed_by_current_email = models.BooleanField(
        _("confirmed by current email"),
        default=False,
    )
    created_at = models.DateTimeField(_("created at"), auto_now_add=True)
    last_modified = models.DateTimeField(_("last modified"), auto_now=True)

    class Meta:
        verbose_name = _("email change request")
        verbose_name_plural = _("email change requests")

    def __str__(self):
        return f"Email change request for {self.current_email} to {self.proposed_email}"

    def is_complete(self):
        """
        Check if the email change request is complete.

        Returns:
            ``bool``: ``True`` if the request is complete, ``False`` otherwise.
        """
        return self.confirmed_by_proposed_email and self.confirmed_by_current_email
