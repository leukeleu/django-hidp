from django.test import RequestFactory, TestCase
from django.urls import reverse

from hidp.accounts import tokens
from hidp.accounts.models import EmailChangeRequest
from hidp.api.serializers import EmailChangeConfirmSerializer, EmailChangeSerializer
from hidp.test.factories.user_factories import EmailChangeRequestFactory, UserFactory


class TestEmailChangeSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:email_change")
        cls.user = UserFactory()
        cls.existing_email_change_request = EmailChangeRequestFactory(user=cls.user)

    def make_serializer(self, proposed_email, password):
        data = {"proposed_email": proposed_email, "password": password}
        request = self.factory.post(self.url, data=data)
        request.user = self.user
        return EmailChangeSerializer(data=data, context={"request": request})

    def test_serializer_invalid_password(self):
        serializer = self.make_serializer(
            password="invalid", proposed_email="heisenberg@example.com"
        )
        self.assertFalse(serializer.is_valid())

    def test_serializer_current_email(self):
        serializer = self.make_serializer(
            password="P@ssw0rd!", proposed_email=self.user.email
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("proposed_email", serializer.errors)

    def test_serializer_valid(self):
        serializer = self.make_serializer(
            password="P@ssw0rd!", proposed_email="heisenberg@example.com"
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        # Old EmailChangeRequest should be deleted
        self.assertFalse(
            EmailChangeRequest.objects.filter(
                id=self.existing_email_change_request.pk
            ).exists()
        )

        # New EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="heisenberg@example.com",
            ).exists()
        )


class TestEmailChangeConfirmSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.user = UserFactory(email="walter@example.com")
        cls.email_change_request = EmailChangeRequestFactory(
            user=cls.user, proposed_email="heisenberg@example.com"
        )
        cls.current_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "current_email"
        )
        cls.proposed_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "proposed_email"
        )
        cls.url = reverse(
            "api:email_change_confirm",
        )

    def make_serializer(self, confirmation_token, instance=None):
        data = {"confirmation_token": confirmation_token}
        request = self.factory.put(self.url, data=data)
        request.user = self.user
        return EmailChangeConfirmSerializer(
            data=data, context={"request": request}, instance=instance
        )

    def test_invalid_token(self):
        serializer = self.make_serializer("invalid")

        self.assertFalse(serializer.is_valid())
        self.assertIn("confirmation_token", serializer.errors)

    def test_current_email_valid_token(self):
        self.client.force_login(UserFactory())
        serializer = self.make_serializer(
            self.current_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_current_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

    def test_proposed_email_valid_token(self):
        self.client.force_login(UserFactory())
        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_proposed_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

    def test_post_second_valid_token(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "heisenberg@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="heisenberg@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())

    def test_post_already_completed_request(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.confirmed_by_proposed_email = True
        self.email_change_request.save()

        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "heisenberg@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="heisenberg@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())
