from http import HTTPStatus

from django.test import TestCase

from ..factories import user_factories

# Note: These tests are mainly an example on how to use factories
#       and the Django test client. Use them as a reference and write
#       exhaustive tests to ensure the application is working as expected.


class TestDjangoAdmin(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.superuser = user_factories.SuperUserFactory()

    def test_django_admin_as_user(self):
        """
        Redirects to login page if user is not a staff or superuser
        """
        self.client.force_login(self.user)
        response = self.client.get("/django-admin/")
        self.assertRedirects(
            response,
            "/django-admin/login/?next=/django-admin/",
            fetch_redirect_response=False,
        )

    def test_django_admin_as_superuser(self):
        """
        Superuser can access the Django admin
        """
        self.client.force_login(self.superuser)
        response = self.client.get("/django-admin/")
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertInHTML(
            f"<strong>{ self.superuser.get_short_name() }</strong>",
            response.content.decode(),
        )
