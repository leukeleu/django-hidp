from rest_framework import serializers

from django.contrib.auth import get_user_model
from hidp.accounts import auth as hidp_auth
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_variables
from django.utils.translation import gettext_lazy as _

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
