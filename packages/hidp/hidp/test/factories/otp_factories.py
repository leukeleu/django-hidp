from factory.django import DjangoModelFactory


class TOTPDeviceFactory(DjangoModelFactory):
    class Meta:
        model = "otp_totp.TOTPDevice"
        django_get_or_create = ("user",)

    name = "Authenticator app"
    confirmed = False


class StaticDeviceFactory(DjangoModelFactory):
    class Meta:
        model = "otp_static.StaticDevice"
        django_get_or_create = ("user",)

    name = "Recovery codes"
    confirmed = False
