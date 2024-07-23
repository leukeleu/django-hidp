import factory

from factory.django import DjangoModelFactory

from django.conf import settings
from django.utils import timezone


class UserFactory(DjangoModelFactory):
    class Meta:
        model = settings.AUTH_USER_MODEL
        skip_postgeneration_save = True

    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.Faker("email")
    password = factory.django.Password("P@ssw0rd!")


class VerifiedUserFactory(UserFactory):
    email_verified = factory.LazyFunction(timezone.now)


class SuperUserFactory(VerifiedUserFactory):
    is_superuser = True
    is_staff = True
