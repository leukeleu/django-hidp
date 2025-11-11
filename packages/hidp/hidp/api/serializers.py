from rest_framework import serializers

import django.core.exceptions as django_exceptions

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import (
    validate_password,
)
from django.contrib.auth.tokens import default_token_generator
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.debug import sensitive_variables

from hidp.accounts import auth as hidp_auth

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


@method_decorator(sensitive_variables("value"), name="validate_token")
@method_decorator(sensitive_variables("value"), name="validate_new_password")
class PasswordResetConfirmationSerializer(serializers.Serializer):
    token = serializers.CharField()
    new_password = serializers.CharField()

    def validate_token(self, value):
        if not default_token_generator.check_token(self.context["request"].user, value):
            raise serializers.ValidationError(_("Invalid or expired token."))
        return value

    def validate_new_password(self, value):
        try:
            validate_password(password=value, user=self.context["request"].user)
        except django_exceptions.ValidationError:
            raise serializers.ValidationError(
                _("Password does not meet requirements.")
            ) from None
        return value
