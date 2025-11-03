from rest_framework import serializers

from django.conf import settings
from django.contrib.auth import get_user_model

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


class SessionSerializer(serializers.Serializer):
    session_key = serializers.CharField(read_only=True)

    def to_representation(self, instance):
        """Session data needs to be read from the model and decoded."""
        representation = super().to_representation(instance)

        if "hidp.api.middleware.AugmentSessionMiddleware" in settings.MIDDLEWARE:
            session_data = instance.get_decoded()

            extra_fields = ["user_agent", "ip_address", "created_at", "last_active"]

            for field in extra_fields:
                field_value = session_data.get(field)
                if field_value:
                    representation[field] = field_value

        return representation
