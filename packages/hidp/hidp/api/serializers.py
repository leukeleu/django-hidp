from rest_framework import serializers

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils.decorators import method_decorator
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
