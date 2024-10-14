from http import HTTPStatus

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from hidp.accounts import tokens
from hidp.accounts.forms import EmailChangeRequestForm
from hidp.accounts.models import EmailChangeRequest
from hidp.test.factories import user_factories


class TestEmailChangeRequest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse("hidp_accounts:email_change_request")

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)

    def test_get(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_request.html"
        )

    def test_get_user_without_password_requests_email_change(self):
        self.user.set_unusable_password()
        self.user.save()

        self.client.force_login(self.user)

        response = self.client.get(self.url)
        self.assertInHTML(
            "You cannot change your email address because you do not have a"
            " password set.",
            response.content.decode(),
        )
        self.assertInHTML(
            "Please set a password first.",
            response.content.decode(),
        )
        self.assertInHTML(
            '<a href="/manage/set-password/">Set password</a>',
            response.content.decode(),
        )

    def test_post_user_without_password_requests_email_change(self):
        self.user.set_unusable_password()
        self.user.save()

        self.client.force_login(self.user)
        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": "newemail@example.com",
            },
        )
        self.assertFalse(response.context["form"].is_valid())
        self.assertIn("password", response.context["form"].errors)

    def test_user_requests_email_change(self):
        with (
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_body.txt"),
        ):  # fmt: skip
            response = self.client.post(
                self.url,
                {
                    "password": "P@ssw0rd!",
                    "proposed_email": "newemail@example.com",
                },
                follow=True,
            )

        self.assertRedirects(
            response, reverse("hidp_accounts:email_change_request_sent")
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_request_sent.html"
        )

        # EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="newemail@example.com",
            ).exists()
        )

        # Email should be sent to current email
        self.assertEqual(len(mail.outbox), 2)

        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, [self.user.email])
        self.assertRegex(
            message.body,
            # Matches the email change confirmation URL:
            # http://testserver/manage/change-email-confirm/eyJ1dWlkIjoiMDE5MjZiNGYtODQ0Zi03MjRmLWE2YjQtMWQxYWEyYTU5OTgwIiwicmVjaXBpZW50IjoiY3VycmVudF9lbWFpbCJ9:1sy5S2:R7m51osUdabcMuOGXZRq7MabESIqKGl_mX2jO-TAcj8/
            r"http://testserver/manage/change-email-confirm/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )

        # Email should be sent to proposed email
        message = mail.outbox[1]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, ["newemail@example.com"])
        self.assertRegex(
            message.body,
            # Matches the email change confirmation URL:
            # http://testserver/manage/change-email-confirm/eyJ1dWlkIjoiMDE5MjZiNGYtODQ0Zi03MjRmLWE2YjQtMWQxYWEyYTU5OTgwIiwicmVjaXBpZW50IjoiY3VycmVudF9lbWFpbCJ9:1sy5S2:R7m51osUdabcMuOGXZRq7MabESIqKGl_mX2jO-TAcj8/
            r"http://testserver/manage/change-email-confirm/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )


class TestEmailChangeRequestForm(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.existing_email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user
        )

    def test_form_invalid_password(self):
        form = EmailChangeRequestForm(
            user=self.user,
            data={
                "password": "invalid",
                "proposed_email": "newemail@example.com",
            },
        )
        self.assertFalse(form.is_valid())

    def test_form_valid(self):
        form = EmailChangeRequestForm(
            user=self.user,
            data={
                "password": "P@ssw0rd!",
                "proposed_email": "newemail@example.com",
            },
        )
        self.assertTrue(form.is_valid())

        form.save()

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
                proposed_email="newemail@example.com",
            ).exists()
        )


class TestEmailChangeConfirm(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user, proposed_email="newemail@example.com"
        )
        cls.current_email_url = reverse(
            "hidp_accounts:email_change_confirm",
            kwargs={
                "token": tokens.email_change_token_generator.make_token(
                    str(cls.email_change_request.pk), "current_email"
                )
            },
        )
        cls.proposed_email_url = reverse(
            "hidp_accounts:email_change_confirm",
            kwargs={
                "token": tokens.email_change_token_generator.make_token(
                    str(cls.email_change_request.pk), "proposed_email"
                )
            },
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated_user(self):
        self.client.logout()
        response = self.client.get(self.current_email_url)

        self.assertEqual(response.status_code, HTTPStatus.FOUND)

    def test_get_invalid_token(self):
        response = self.client.get(
            reverse(
                "hidp_accounts:email_change_confirm",
                kwargs={"token": "invalid"},
            ),
            follow=True,
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_confirm.html"
        )
        self.assertInHTML(
            "The link you followed is invalid."
            " It may have expired or been used already.",
            response.content.decode(),
        )

    def test_valid_token_wrong_user(self):
        self.client.force_login(user_factories.UserFactory())
        response = self.client.get(self.current_email_url, follow=True)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_confirm.html"
        )
        self.assertInHTML(
            "The link you followed is invalid."
            " It may have expired or been used already.",
            response.content.decode(),
        )

    def test_get_valid_token(self):
        response = self.client.get(self.current_email_url, follow=True)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_confirm.html"
        )
        self.assertIn("validlink", response.context)

    def test_get_already_confirmed(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        response = self.client.get(self.current_email_url, follow=True)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_confirm.html"
        )
        self.assertInHTML(
            "You have already confirmed the change from this email address.",
            response.content.decode(),
        )
        self.assertInHTML(
            "Please go to your other inbox and look for the link there.",
            response.content.decode(),
        )

    def test_post_current_email_valid_token(self):
        response = self.client.post(
            self.current_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertRedirects(
            response, reverse("hidp_accounts:email_change_complete"), status_code=308
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Successfully confirmed the change from your current email address.",
            response.content.decode(),
        )
        self.assertInHTML(
            "You also need to confirm the change from your new email.",
            response.content.decode(),
        )
        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_current_email, True)

    def test_post_proposed_email_valid_token(self):
        response = self.client.post(
            self.proposed_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertRedirects(
            response, reverse("hidp_accounts:email_change_complete"), status_code=308
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Successfully confirmed the change from your new email address.",
            response.content.decode(),
        )
        self.assertInHTML(
            "You also need to confirm the change from your current email.",
            response.content.decode(),
        )
        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_proposed_email, True)

    def test_post_second_valid_token(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        response = self.client.post(
            self.proposed_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertRedirects(
            response, reverse("hidp_accounts:email_change_complete"), status_code=308
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Successfully confirmed the change from both your current and new "
            " email address.",
            response.content.decode(),
        )
        self.assertInHTML(
            "Your email address has been changed.",
            response.content.decode(),
        )

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "newemail@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="newemail@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())
