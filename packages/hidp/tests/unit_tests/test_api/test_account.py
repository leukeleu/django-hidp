from datetime import timedelta
from http import HTTPStatus

from rest_framework.test import APITestCase

from django.contrib.auth import SESSION_KEY
from django.core import mail
from django.test import override_settings
from django.urls import reverse
from django.utils import timezone

from hidp.api.serializers import UserSerializer, get_user_serializer_class
from hidp.test.factories.user_factories import (
    EmailChangeRequestFactory,
    VerifiedUserFactory,
)


class StaffUserSerializer(UserSerializer):
    writable_fields = (*UserSerializer.writable_fields, "is_staff")

    class Meta(UserSerializer.Meta):
        fields = [*UserSerializer.Meta.fields, "is_staff"]


class TestPasswordChangeView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:password_change")

    def setUp(self):
        self.user = VerifiedUserFactory()
        self.client.force_login(self.user)

    def test_change_password(self):
        response = self.client.post(
            self.url,
            {"old_password": "P@ssw0rd!", "new_password": "N3w-P@ssw0rd!"},
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("N3w-P@ssw0rd!"))
        self.assertEqual(mail.outbox[0].subject, "Your password has been changed")
        self.assertIn("http://testserver/frontend/reset/", mail.outbox[0].body)

    def test_session_stays_valid(self):
        self.client.post(
            self.url,
            {"old_password": "P@ssw0rd!", "new_password": "N3w-P@ssw0rd!"},
        )

        response = self.client.get(reverse("hidp_api:session"))

        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_wrong_old_password(self):
        response = self.client.post(
            self.url, {"old_password": "wrong", "new_password": "N3w-P@ssw0rd!"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(set(response.json()), {"old_password"})

    @override_settings(
        AUTH_PASSWORD_VALIDATORS=[
            {"NAME": ("django.contrib.auth.password_validation.MinimumLengthValidator")}
        ]
    )
    def test_invalid_new_password(self):
        response = self.client.post(
            self.url, {"old_password": "P@ssw0rd!", "new_password": "short"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertEqual(set(response.json()), {"new_password"})

    def test_user_without_password(self):
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_login(self.user)

        response = self.client.post(
            self.url, {"old_password": "", "new_password": "N3w-P@ssw0rd!"}
        )

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "password_not_set")

    def test_unauthenticated(self):
        self.client.logout()

        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)


class TestSetPasswordView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:set_password")

    def setUp(self):
        self.user = VerifiedUserFactory(last_login=timezone.now())
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_login(self.user)

    def test_set_password(self):
        response = self.client.post(self.url, {"new_password": "N3w-P@ssw0rd!"})

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("N3w-P@ssw0rd!"))
        self.assertIn(SESSION_KEY, self.client.session)
        self.assertEqual(len(mail.outbox), 1)

    def test_requires_recent_login(self):
        self.user.last_login = timezone.now() - timedelta(minutes=6)
        self.user.save()

        response = self.client.post(self.url, {"new_password": "N3w-P@ssw0rd!"})

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "reauthentication_required")

    def test_user_with_password(self):
        self.user.set_password("P@ssw0rd!")
        self.user.save()
        self.client.force_login(self.user)

        response = self.client.post(self.url, {"new_password": "N3w-P@ssw0rd!"})

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "password_already_set")


class TestEmailChangeStatus(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:email_change")
        cls.user = VerifiedUserFactory(email="walter@example.com")

    def setUp(self):
        self.client.force_login(self.user)

    def test_no_pending_request(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_pending_request(self):
        EmailChangeRequestFactory(
            user=self.user,
            current_email="walter@example.com",
            proposed_email="heisenberg@example.com",
            confirmed_by_current_email=True,
        )

        response = self.client.get(self.url)

        self.assertEqual(
            response.json(),
            {
                "current_email": "walter@example.com",
                "proposed_email": "heisenberg@example.com",
                "confirmed_by_current_email": True,
                "confirmed_by_proposed_email": False,
            },
        )


class TestUserSerializerSetting(APITestCase):
    """HIDP_API_USER_SERIALIZER changes the user in the auth state and at /users/me/."""

    def setUp(self):
        self.user = VerifiedUserFactory()
        self.client.force_login(self.user)

    @override_settings(
        HIDP_API_USER_SERIALIZER=f"{__name__}.{StaffUserSerializer.__name__}"
    )
    def test_custom_serializer(self):
        session = self.client.get(reverse("hidp_api:session")).json()
        me = self.client.get(reverse("hidp_api:user")).json()

        self.assertFalse(session["user"]["is_staff"])
        self.assertEqual(session["user"], me)

    @override_settings(
        HIDP_API_USER_SERIALIZER=f"{__name__}.{StaffUserSerializer.__name__}"
    )
    def test_custom_writable_field(self):
        self.client.patch(reverse("hidp_api:user"), {"is_staff": True})

        self.user.refresh_from_db()
        self.assertTrue(self.user.is_staff)

    @override_settings(HIDP_API_USER_SERIALIZER="tests.does.not.Exist")
    def test_import_error_uses_default(self):
        with self.assertLogs("hidp.api.serializers", level="ERROR"):
            self.assertIs(get_user_serializer_class(), UserSerializer)

    @override_settings(HIDP_API_USER_SERIALIZER="hidp.api.serializers.LoginSerializer")
    def test_other_serializer_uses_default(self):
        with self.assertLogs("hidp.api.serializers", level="ERROR"):
            self.assertIs(get_user_serializer_class(), UserSerializer)
