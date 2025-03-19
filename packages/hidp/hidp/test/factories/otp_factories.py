import factory

from django_otp.plugins.otp_static.models import StaticToken
from factory.django import DjangoModelFactory


class TOTPDeviceFactory(DjangoModelFactory):
    class Meta:
        model = "otp_totp.TOTPDevice"

    name = "Authenticator app"
    confirmed = False


class StaticDeviceFactory(DjangoModelFactory):
    class Meta:
        model = "otp_static.StaticDevice"

    name = "Recovery codes"
    confirmed = False


class StaticTokenFactory(DjangoModelFactory):
    class Meta:
        model = StaticToken

    device = factory.SubFactory(StaticDeviceFactory)
    token = factory.LazyFunction(StaticToken.random_token)
