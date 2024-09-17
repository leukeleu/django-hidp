from rest_framework import mixins, viewsets
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import get_user_model

from .serializers import UserSerializer

UserModel = get_user_model()


class UserViewSet(mixins.UpdateModelMixin, viewsets.GenericViewSet):
    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]
    queryset = UserModel.objects.all()

    def get_queryset(self):
        return self.queryset.filter(pk=self.request.user.pk)
