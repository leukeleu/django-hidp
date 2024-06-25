import factory

from factory.django import DjangoModelFactory


class UserFactory(DjangoModelFactory):
    class Meta:
        model = "hidp_accounts.User"
        skip_postgeneration_save = True

    first_name = factory.Faker("first_name")
    last_name = factory.Faker("last_name")
    email = factory.Faker("email")
    password = factory.django.Password("P@ssw0rd!")

    # Call the `clean` method after creating the user
    clean = factory.PostGenerationMethodCall("clean")


class SuperUserFactory(UserFactory):
    is_superuser = True
    is_staff = True
