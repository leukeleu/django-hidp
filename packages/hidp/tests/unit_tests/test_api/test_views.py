from rest_framework.test import APITestCase

from django.urls import reverse

from hidp.test.factories import user_factories


class TestUserViewSet(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(first_name="Walter", last_name="White")
        cls.update_url = reverse("api:user-detail", kwargs={"pk": cls.user.pk})

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_queryset(self):
        response = self.client.get(self.update_url)
        self.assertEqual(response.status_code, 405)

    def test_update_user_unauthenticated(self):
        self.client.logout()
        response = self.client.patch(
            self.update_url,
            data={"first_name": "Jesse"},
        )
        self.assertEqual(response.status_code, 403)

    def test_update_other_user(self):
        other_user = user_factories.UserFactory()
        response = self.client.patch(
            reverse("api:user-detail", kwargs={"pk": other_user.pk}),
            data={"first_name": "Jesse"},
        )
        self.assertEqual(response.status_code, 404)

    def test_update_user_with_patch(self):
        with self.subTest("Patch without all required fields should partially update."):
            response = self.client.patch(
                self.update_url,
                data={"first_name": "Jesse"},
            )
            self.assertEqual(response.status_code, 200)
            self.user.refresh_from_db()
            self.assertEqual(self.user.first_name, "Jesse")
            self.assertEqual(self.user.last_name, "White")

        with self.subTest("Patch with all required fields should update the user."):
            response = self.client.patch(
                self.update_url,
                data={"first_name": "Gus", "last_name": "Fring"},
            )
            self.assertEqual(response.status_code, 200)
            self.user.refresh_from_db()
            self.assertEqual(self.user.first_name, "Gus")
            self.assertEqual(self.user.last_name, "Fring")

    def test_update_user_with_put(self):
        with self.subTest("Put without all required fields should throw an error."):
            response = self.client.put(
                self.update_url,
                data={"first_name": "Jesse"},
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(
                '{"last_name":["This field is required."]}',
                response.content.decode("utf-8"),
            )
            self.user.refresh_from_db()
            self.assertEqual(self.user.first_name, "Walter")

        with self.subTest("Put with all required fields should update the user."):
            response = self.client.put(
                self.update_url,
                data={"first_name": "Jesse", "last_name": "Pinkman"},
            )
            self.assertEqual(response.status_code, 200)
            self.user.refresh_from_db()
            self.assertEqual(self.user.first_name, "Jesse")
            self.assertEqual(self.user.last_name, "Pinkman")
