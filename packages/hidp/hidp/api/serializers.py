from rest_framework import serializers

import django.core.exceptions as django_exceptions

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password,
)
from django.contrib.auth.tokens import default_token_generator
from django.db import IntegrityError, transaction
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from hidp.accounts import auth as hidp_auth
from hidp.accounts import tokens
from hidp.accounts.email_change import Recipient
from hidp.accounts.models import EmailChangeRequest

UserModel = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = UserModel
        fields = [
            "first_name",
            "last_name",
            "email",
        ]
        read_only_fields = ["email"]


@method_decorator(sensitive_variables(), name="validate")
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(write_only=True)
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        user = hidp_auth.authenticate(
            request=self.context.get("request"),
            username=attrs.get("username"),
            password=attrs.get("password"),
        )
        if not user:
            raise serializers.ValidationError(
                _("Could not authenticate"), code="authorization"
            )
        attrs["user"] = user
        return attrs


@method_decorator(sensitive_variables(), name="validate")
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, attrs):  # noqa: PLR6301
        """
        Validates that the email corresponds to an active user.

        Returns the user in the validated data if found, else None.
        """
        attrs["user"] = UserModel.objects.filter(
            email__iexact=attrs["email"], is_active=True
        ).first()
        return attrs


@method_decorator(sensitive_variables(), name="_validate_new_password")
@method_decorator(sensitive_variables(), name="validate")
@method_decorator(sensitive_variables(), name="get_user")
class PasswordResetConfirmationSerializer(serializers.Serializer):
    token = serializers.CharField()
    uidb64 = serializers.CharField()
    new_password = serializers.CharField()

    def _validate_new_password(self, user, value):  # noqa: PLR6301
        """
        Validate that the password meets all validator requirements.

        Raises a ValidationError if the password is invalid.
        """
        try:
            validate_password(password=value, user=user)
        except django_exceptions.ValidationError as exc:
            raise serializers.ValidationError(exc.messages) from None

    def get_user(self, uidb64):  # noqa: PLR6301
        """
        Taken from Django's `PasswordResetConfirmView.get_user`.

        This is used so we consistently handle the uidb64 in both the template views and
        API views when decoding the user ID and retrieving the user from the database.
        """
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel.objects.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            django_exceptions.ValidationError,
        ):
            user = None
        return user

    def validate(self, attrs):
        """
        Validates that the token and uidb64 correspond to a valid user.

        If valid, runs password validation on the new password.
        """
        user = self.get_user(attrs["uidb64"])

        if not user or not default_token_generator.check_token(user, attrs["token"]):
            raise serializers.ValidationError(_("Invalid token or user ID."))

        self._validate_new_password(user, attrs["new_password"])
        return attrs


class EmailChangeSerializer(serializers.Serializer):
    proposed_email = serializers.EmailField(
        write_only=True, required=True, max_length=254
    )
    password = serializers.CharField(write_only=True, required=True)

    def validate_password(self, value):
        """
        Validate the password.

        Returns the password if it is correct, otherwise raises a `ValidationError`.
        """
        user = self.context.get("request").user

        if not user.check_password(value):
            raise serializers.ValidationError(
                _("The password is incorrect."), code="authorization"
            )

        return value

    def validate_proposed_email(self, value):
        """
        Validate the proposed email address.

        Returns the proposed email address if it is different from the current email
        address of the user, otherwise raises a `ValidationError`.
        """
        user = self.context.get("request").user

        if value == user.email:
            raise serializers.ValidationError(
                _("The new email address is the same as the current email address.")
            )

        return value

    def create(self, validated_data):
        """
        Create an email change request.

        Replaces any existing email change requests for the user.

        Returns:
            The email change request.
        """
        user = self.context.get("request").user

        instance = EmailChangeRequest(proposed_email=validated_data["proposed_email"])
        instance.user = user
        instance.current_email = user.email

        with transaction.atomic():
            # Remove existing email change requests for the user, if any.
            EmailChangeRequest.objects.filter(user=user).delete()
            instance.save()

        return instance


class EmailChangeConfirmSerializer(serializers.Serializer):
    confirmation_token = serializers.CharField(write_only=True, required=True)

    def validate_confirmation_token(self, value):  # noqa: PLR6301 (no-self-use)
        """
        Validate the confirmation token.

        Returns a dictionary of the data inside the token if it is
        valid and not expired, otherwise raises a `ValidationError`.
        """
        token_data = tokens.email_change_token_generator.check_token(value)

        if (
            not token_data
            or not set(token_data.keys()) == {"recipient", "uuid"}
            or token_data["recipient"]
            not in {Recipient.CURRENT_EMAIL, Recipient.PROPOSED_EMAIL}
        ):
            raise serializers.ValidationError(_("Invalid or expired token."))

        return token_data

    def update(self, instance, validated_data):  # noqa: PLR6301 (no-self-use)
        # Update the change object
        match validated_data["confirmation_token"]["recipient"]:
            case Recipient.CURRENT_EMAIL:
                instance.confirmed_by_current_email = True
            case Recipient.PROPOSED_EMAIL:
                instance.confirmed_by_proposed_email = True

        # Change email address of user if complete.
        with transaction.atomic():
            instance.save()
            if instance.is_complete():
                instance.user.email = instance.proposed_email
                try:
                    instance.user.save(update_fields=["email"])
                except IntegrityError:
                    # Should only happen if an account was created with the proposed
                    # email address after email change request was made.
                    raise serializers.ValidationError(
                        _("An account with this email address already exists.")
                    ) from None

        return instance
