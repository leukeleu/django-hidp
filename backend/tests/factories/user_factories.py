import factory

from factory.django import DjangoModelFactory


class UserFactory(DjangoModelFactory):
    class Meta:
        model = "accounts.User"

    username = factory.Faker("user_name")
    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.Faker("email")
    password = factory.django.Password("P@ssw0rd!")


class SuperUserFactory(UserFactory):
    is_superuser = True
    is_staff = True
