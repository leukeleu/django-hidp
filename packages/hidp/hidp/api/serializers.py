import functools
import logging

from rest_framework import serializers
from rest_framework.exceptions import ErrorDetail
from rest_framework.settings import api_settings

import django.core.exceptions as django_exceptions

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import default_token_generator
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from hidp.accounts import forms, tokens
from hidp.accounts.email_change import get_email_change_request_from_token_data
from hidp.accounts.email_verification import get_unverified_user_from_token
from hidp.accounts.models import EmailChangeRequest

from ..constants import Step

UserModel = get_user_model()

logger = logging.getLogger(__name__)


class UserSerializer(serializers.ModelSerializer):
    """The user in the authentication state, and at `/users/me/`."""

    # Every other field is read-only.
    writable_fields = ("first_name", "last_name")

    first_name = serializers.CharField(max_length=150)
    last_name = serializers.CharField(max_length=150)
    has_usable_password = serializers.BooleanField(read_only=True)

    class Meta:
        model = UserModel
        fields = [
            "id",
            "first_name",
            "last_name",
            "email",
            "has_usable_password",
        ]

    def get_fields(self):
        fields = super().get_fields()
        for name, field in fields.items():
            if name not in self.writable_fields:
                field.read_only = True
                field.required = False
        return fields


def import_user_serializer(path):
    """Import the serializer at `path`, or raise ImportError or TypeError."""
    serializer_class = import_string(path)
    if not (
        isinstance(serializer_class, type)
        and issubclass(serializer_class, UserSerializer)
    ):
        msg = f"{path!r} is not a subclass of {UserSerializer.__name__}."
        raise TypeError(msg)
    return serializer_class


@functools.cache
def _import_user_serializer(path):
    try:
        return import_user_serializer(path)
    except (ImportError, TypeError):
        logger.exception(
            "HIDP_API_USER_SERIALIZER %r is not usable, using %s.",
            path,
            UserSerializer.__name__,
        )
        return UserSerializer


def get_user_serializer_class():
    """Return the serializer named by `HIDP_API_USER_SERIALIZER`, or the default."""
    path = getattr(settings, "HIDP_API_USER_SERIALIZER", None)
    return _import_user_serializer(path) if path else UserSerializer


class PendingStepSerializer(serializers.Serializer):
    step = serializers.ChoiceField(choices=[step.value for step in Step])


class AuthStateSerializer(serializers.Serializer):
    pending = PendingStepSerializer(many=True)

    def get_fields(self):
        return {"user": get_user_serializer_class()(allow_null=True)} | (
            super().get_fields()
        )


def _form_errors(form, field_names):
    errors = {}
    for form_field, form_errors in form.errors.get_json_data().items():
        if form_field == django_exceptions.NON_FIELD_ERRORS:
            key = api_settings.NON_FIELD_ERRORS_KEY
        else:
            key = field_names.get(form_field, form_field)
        messages = errors.setdefault(key, [])
        for error in form_errors:
            if error["message"] not in messages:
                messages.append(ErrorDetail(error["message"], code=error["code"]))
    return errors


class FormSerializer(serializers.Serializer):
    """
    Validate the request data with a Django form, after the serializer fields.

    The form's errors become DRF errors, and the valid form is kept as `form`.
    """

    form_class = NotImplemented
    # Serializer field name to the form fields it fills, where they differ.
    form_fields = {}

    def get_form_kwargs(self, attrs):  # noqa: PLR6301 (no-self-use)
        return {}

    def get_form_data(self, attrs):
        data = {}
        for name, value in attrs.items():
            for form_field in self.form_fields.get(name, [name]):
                data[form_field] = value
        return data

    @method_decorator(sensitive_variables())
    def validate(self, attrs):
        self.form = self.form_class(
            data=self.get_form_data(attrs), **self.get_form_kwargs(attrs)
        )
        if not self.form.is_valid():
            field_names = {
                form_field: name
                for name, form_fields in self.form_fields.items()
                for form_field in form_fields
            }
            raise serializers.ValidationError(_form_errors(self.form, field_names))
        return attrs

    @property
    def request(self):
        return self.context["request"]


class LoginSerializer(FormSerializer):
    form_class = forms.AuthenticationForm

    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def get_form_kwargs(self, attrs):
        return {"request": self.request}


class SignupSerializer(FormSerializer):
    form_class = forms.UserCreationForm
    form_fields = {
        "email": [UserModel.USERNAME_FIELD],
        "password": ["password1", "password2"],
    }

    email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)
    agreed_to_tos = serializers.BooleanField(write_only=True)

    def get_form_kwargs(self, attrs):
        return {"request": self.request}


class EmailVerificationTokenSerializer(serializers.Serializer):
    token = serializers.CharField(write_only=True)

    def validate_token(self, value):  # noqa: PLR6301 (no-self-use)
        """Return the unverified user the emailed verification token belongs to."""
        user = get_unverified_user_from_token(
            value, token_generator=tokens.email_verification_token_generator
        )
        if user is None:
            raise serializers.ValidationError(_("Invalid or expired token."))
        return user

    def validate(self, attrs):
        attrs["user"] = attrs.pop("token")
        return super().validate(attrs)


class EmailVerificationConfirmSerializer(
    EmailVerificationTokenSerializer, FormSerializer
):
    """Confirm the email address, with a name when the user does not have one yet."""

    form_class = forms.EmailVerificationForm

    first_name = serializers.CharField(write_only=True, required=False)
    last_name = serializers.CharField(write_only=True, required=False)

    def get_form_kwargs(self, attrs):  # noqa: PLR6301 (no-self-use)
        return {"instance": attrs["user"]}


class PasswordResetRequestSerializer(FormSerializer):
    form_class = forms.PasswordResetRequestForm

    email = serializers.EmailField(write_only=True)


class PasswordResetConfirmationSerializer(FormSerializer):
    form_class = forms.PasswordResetForm
    form_fields = {"new_password": ["new_password1", "new_password2"]}

    token = serializers.CharField(write_only=True)
    uidb64 = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    @staticmethod
    def _get_user(uidb64):
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            return UserModel.objects.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            django_exceptions.ValidationError,
        ):
            return None

    @method_decorator(sensitive_variables())
    def validate(self, attrs):
        user = self._get_user(attrs["uidb64"])
        if user is None or not default_token_generator.check_token(
            user, attrs["token"]
        ):
            raise serializers.ValidationError(_("Invalid token or user ID."))
        self.user = user
        return super().validate(attrs)

    def get_form_kwargs(self, attrs):
        return {"user": self.user}


class PasswordChangeSerializer(FormSerializer):
    form_class = forms.PasswordChangeForm
    form_fields = {"new_password": ["new_password1", "new_password2"]}

    old_password = serializers.CharField(write_only=True, trim_whitespace=False)
    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def get_form_kwargs(self, attrs):
        return {"user": self.request.user}


class SetPasswordSerializer(FormSerializer):
    form_class = forms.SetPasswordForm
    form_fields = {"new_password": ["new_password1", "new_password2"]}

    new_password = serializers.CharField(write_only=True, trim_whitespace=False)

    def get_form_kwargs(self, attrs):
        return {"user": self.request.user}


class EmailChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailChangeRequest
        fields = [
            "current_email",
            "proposed_email",
            "confirmed_by_current_email",
            "confirmed_by_proposed_email",
        ]
        read_only_fields = fields


class EmailChangeRequestSerializer(FormSerializer):
    form_class = forms.EmailChangeRequestForm

    proposed_email = serializers.EmailField(write_only=True)
    password = serializers.CharField(write_only=True, trim_whitespace=False)

    def get_form_kwargs(self, attrs):
        return {"user": self.request.user}


class EmailChangeConfirmSerializer(FormSerializer):
    form_class = forms.EmailChangeConfirmForm

    token = serializers.CharField(write_only=True)

    def validate_token(self, value):
        """Return the email change request of the user that the token confirms."""
        token_data = tokens.email_change_token_generator.check_token(value)
        email_change_request = get_email_change_request_from_token_data(
            self.request.user, token_data
        )
        if email_change_request is None:
            raise serializers.ValidationError(_("Invalid or expired token."))
        self.recipient = token_data["recipient"]
        return email_change_request

    def get_form_data(self, attrs):  # noqa: PLR6301 (no-self-use)
        # Posting the token is the consent the HTML form asks for.
        return {"allow_change": True}

    def get_form_kwargs(self, attrs):
        return {"instance": attrs["token"], "recipient": self.recipient}
