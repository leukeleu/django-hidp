from rest_framework import serializers

from django.contrib.auth import authenticate, get_user_model
from django.utils.decorators import method_decorator
from django.views.decorators.debug import sensitive_variables

from .constants import LoginGrant

UserModel = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=True)

    class Meta:
        model = UserModel
        fields = ["first_name", "last_name"]


@method_decorator(sensitive_variables(), name="validate")
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    grant = serializers.ChoiceField(choices=LoginGrant.choices)

    def validate(self, attrs):
        user = authenticate(
            request=self.context.get("request"),
            username=attrs.get("username"),
            password=attrs.get("password"),
        )
        if not user:
            raise serializers.ValidationError(
                "Could not authenticate", code="authorization"
            )
        attrs["user"] = user
        return attrs
