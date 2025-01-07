import io

from http import HTTPStatus
from unittest import mock

from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from hidp.accounts import tokens
from hidp.accounts.email_change import remove_complete_and_stale_email_change_requests
from hidp.accounts.forms import EmailChangeRequestForm
from hidp.accounts.models import EmailChangeRequest
from hidp.test.factories import user_factories


class TestEmailChangeRequest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse("hidp_account_management:email_change_request")

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
            "Your account does not currently have a password set.",
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
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_body.html"),
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
            response, reverse("hidp_account_management:email_change_request_sent")
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
        self.assertIn(
            "http://testserver/manage/change-email-cancel/",
            message.body,
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
        self.assertIn(
            "http://testserver/manage/change-email-cancel/",
            message.body,
        )

    def test_email_change_proposed_email_exists(self):
        """
        Pretend that the email change request was successful.

        When the user requests an email change to an email address that already exists,
        we pretend that the email change request was successful and send an email to the
        current email address, but a different one to the proposed one.
        """
        user_factories.UserFactory(email="existing@example.com")
        with (
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/email_change_body.html"),
            self.assertTemplateUsed("hidp/accounts/management/email/proposed_email_exists_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/proposed_email_exists_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/proposed_email_exists_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.url,
                {
                    "password": "P@ssw0rd!",
                    "proposed_email": "existing@example.com",
                },
                follow=True,
            )

        self.assertRedirects(
            response, reverse("hidp_account_management:email_change_request_sent")
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_request_sent.html"
        )

        # EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="existing@example.com",
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
        self.assertIn(
            "http://testserver/manage/change-email-cancel/",
            message.body,
        )

        # A different email should be sent to proposed email
        message = mail.outbox[1]
        self.assertEqual(
            message.subject,
            "Email change request",
        )
        self.assertEqual(message.to, ["existing@example.com"])
        self.assertIn(
            "However, you already have an account that uses existing@example.com",
            message.body,
        )
        self.assertIn(
            "http://testserver/manage/change-email-cancel/",
            message.body,
        )

    def test_proposed_email_user_inactive(self):
        inactive_user = user_factories.UserFactory(is_active=False)

        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": inactive_user.email,
            },
            follow=True,
        )

        self.assertRedirects(
            response, reverse("hidp_account_management:email_change_request_sent")
        )

        # Email should be sent to current email, but not to proposed email (inactive)
        self.assertEqual(len(mail.outbox), 1)

        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, [self.user.email])


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

    def test_form_current_email(self):
        form = EmailChangeRequestForm(
            user=self.user,
            data={
                "password": "P@ssw0rd!",
                "proposed_email": self.user.email,
            },
        )
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid")
        self.assertIn(
            "The new email address is the same as the current email address.",
            form.errors["proposed_email"],
        )

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
        cls.user = user_factories.UserFactory(email="current@example.com")
        cls.email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user, proposed_email="newemail@example.com"
        )
        cls.current_email_url = reverse(
            "hidp_account_management:email_change_confirm",
            kwargs={
                "token": tokens.email_change_token_generator.make_token(
                    str(cls.email_change_request.pk), "current_email"
                )
            },
        )
        cls.proposed_email_url = reverse(
            "hidp_account_management:email_change_confirm",
            kwargs={
                "token": tokens.email_change_token_generator.make_token(
                    str(cls.email_change_request.pk), "proposed_email"
                )
            },
        )

    def setUp(self):
        self.client.force_login(self.user)

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        if validlink:
            self.assertTemplateUsed(
                response, "hidp/accounts/management/email_change_confirm.html"
            )
        else:
            self.assertTemplateUsed(
                response,
                "hidp/accounts/management/email_change_confirm_invalid_link.html",
            )

    def test_get_unauthenticated_user(self):
        self.client.logout()
        response = self.client.get(self.current_email_url)

        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        self.assertRedirects(
            response, f"{reverse('hidp_accounts:login')}?next={self.current_email_url}"
        )

    def test_get_invalid_token(self):
        self._assert_response(
            self.client.get(
                reverse(
                    "hidp_account_management:email_change_confirm",
                    kwargs={"token": "invalid"},
                ),
                follow=True,
            ),
            validlink=False,
        )

    def test_no_token_in_session(self):
        """Placeholder token, no token in session."""
        self._assert_response(
            self.client.get(
                reverse(
                    "hidp_account_management:email_change_confirm",
                    kwargs={"token": "email-change"},
                ),
                follow=True,
            ),
            validlink=False,
        )

    def test_valid_token_wrong_user(self):
        self.client.force_login(user_factories.UserFactory())

        self._assert_response(
            self.client.get(self.current_email_url, follow=True), validlink=False
        )

    def test_get_valid_token(self):
        self._assert_response(self.client.get(self.current_email_url, follow=True))

    def test_get_already_confirmed(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        self._assert_response(
            self.client.get(self.current_email_url, follow=True), validlink=False
        )

    def test_post_current_email_valid_token(self):
        response = self.client.post(
            self.current_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertRedirects(
            response,
            reverse("hidp_account_management:email_change_complete"),
            status_code=307,
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Please also confirm the change from your new email address.",
            response.content.decode(),
        )
        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_current_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "current@example.com")

        # Email changed mail should not be sent yet
        self.assertEqual(len(mail.outbox), 0)

    def test_post_proposed_email_valid_token(self):
        response = self.client.post(
            self.proposed_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertRedirects(
            response,
            reverse("hidp_account_management:email_change_complete"),
            status_code=307,
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Please also confirm the change from your current email address.",
            response.content.decode(),
        )
        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_proposed_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "current@example.com")

        # Email changed mail should not be sent yet
        self.assertEqual(len(mail.outbox), 0)

    def test_post_second_valid_token(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        with (
            self.assertTemplateUsed("hidp/accounts/management/email/email_changed_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/email_changed_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/email_changed_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.proposed_email_url, {"allow_change": "on"}, follow=True
            )

        self.assertRedirects(
            response,
            reverse("hidp_account_management:email_change_complete"),
            status_code=307,
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_complete.html"
        )
        self.assertInHTML(
            "Your account email address has been changed successfully.",
            response.content.decode(),
        )

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "newemail@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="newemail@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())

        # Email changed mail should be sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            "Your account email address has been changed",
            mail.outbox[0].subject,
        )
        self.assertEqual(
            mail.outbox[0].to,
            ["current@example.com", "newemail@example.com"],
        )

    def test_post_invalid_token(self):
        self._assert_response(
            self.client.post(
                reverse(
                    "hidp_account_management:email_change_confirm",
                    kwargs={"token": "invalid"},
                ),
                {"allow_change": "on"},
                follow=True,
            ),
            validlink=False,
        )

    def test_post_proposed_email_already_exists(self):
        # Should only happen if an account was created with the proposed email
        # address after email change request was made.
        user_factories.UserFactory(email="newemail@example.com")
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        response = self.client.post(
            self.proposed_email_url, {"allow_change": "on"}, follow=True
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(
            response.context["form"].is_valid(), msg="Expected form to be invalid"
        )
        self.assertIn(
            "Sorry, changing your email address is not possible because an"
            " account with this email address already exists.",
            response.context["form"].errors["__all__"],
        )

    def test_post_already_completed_request(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.confirmed_by_proposed_email = True
        self.email_change_request.save()

        self._assert_response(
            self.client.post(
                self.current_email_url, {"allow_change": "on"}, follow=True
            ),
            validlink=False,
        )


class TestEmailChangeCancel(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user
        )
        cls.url = reverse("hidp_account_management:email_change_cancel")

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated_user(self):
        self.client.logout()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        self.assertRedirects(
            response, f"{reverse('hidp_accounts:login')}?next={self.url}"
        )

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        if validlink:
            self.assertTemplateUsed(
                response, "hidp/accounts/management/email_change_cancel.html"
            )
        else:
            self.assertTemplateUsed(
                response,
                "hidp/accounts/management/email_change_cancel_invalid_link.html",
            )

    def test_get_no_change_request(self):
        self.email_change_request.delete()

        self._assert_response(self.client.get(self.url), validlink=False)

    def test_get_completed_change_request(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.confirmed_by_proposed_email = True
        self.email_change_request.save()

        self._assert_response(self.client.get(self.url), validlink=False)

    def test_get(self):
        self._assert_response(self.client.get(self.url))

    def test_post_expired_change_request(self):
        self.email_change_request.created_at = timezone.now() - timezone.timedelta(
            days=8
        )
        self.email_change_request.save()

        self._assert_response(
            self.client.post(self.url, {"allow_cancel": "on"}), validlink=False
        )

    def test_post_no_change_request(self):
        self.email_change_request.delete()

        self._assert_response(
            self.client.post(self.url, {"allow_cancel": "on"}), validlink=False
        )

    def test_post(self):
        response = self.client.post(self.url, {"allow_cancel": "on"}, follow=True)
        self.assertRedirects(
            response,
            reverse("hidp_account_management:email_change_cancel_done"),
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_cancel_done.html"
        )

        self.assertFalse(
            EmailChangeRequest.objects.filter(
                user=self.user,
            ).exists()
        )


class TestRemoveIncompleteEmailChangeRequests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.stale_request = user_factories.EmailChangeRequestFactory()
        cls.stale_request.created_at = timezone.now() - timezone.timedelta(days=14)
        cls.stale_request.save()

        cls.incomplete_recent_request = user_factories.EmailChangeRequestFactory()
        cls.incomplete_recent_request.created_at = timezone.now() - timezone.timedelta(
            days=3
        )
        cls.incomplete_recent_request.save()

        cls.completed_request = user_factories.EmailChangeRequestFactory(
            confirmed_by_current_email=True,
            confirmed_by_proposed_email=True,
        )
        cls.completed_request.created_at = timezone.now() - timezone.timedelta(days=1)
        cls.completed_request.save()

    def test_remove_complete_and_stale_email_change_requests_dry_run(self):
        removed_requests = remove_complete_and_stale_email_change_requests(dry_run=True)
        email_change_requests_exist = (
            EmailChangeRequest.objects.filter(pk=email_change_request.pk).exists()
            for email_change_request in (
                self.stale_request,
                self.incomplete_recent_request,
                self.completed_request,
            )
        )
        self.assertEqual(
            removed_requests,
            2,
            msg="Expected 2 requests to be selected for removal.",
        )
        self.assertTrue(
            all(email_change_requests_exist),
            msg="Expected all requests to still exist after dry run.",
        )

    def test_remove_complete_and_stale_email_change_requests(self):
        removed_requests = remove_complete_and_stale_email_change_requests()
        self.assertEqual(
            removed_requests,
            2,
            msg="Expected 2 requests to be selected for removal.",
        )
        self.assertFalse(
            EmailChangeRequest.objects.filter(pk=self.stale_request.pk).exists(),
            msg="Expected stale request to be removed, created more than 7 days ago.",
        )
        self.assertFalse(
            EmailChangeRequest.objects.filter(pk=self.completed_request.pk).exists(),
            msg="Expected complete request to be removed.",
        )
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                pk=self.incomplete_recent_request.pk
            ).exists(),
            msg=(
                "Expected incomplete recent request to still exist, created less"
                " than 7 days ago.",
            ),
        )

    def test_remove_complete_and_stale_email_change_requests_2_days(self):
        removed_requests = remove_complete_and_stale_email_change_requests(days=2)
        self.assertEqual(
            removed_requests,
            3,
            msg="Expected 3 requests to be selected for removal.",
        )
        self.assertFalse(
            EmailChangeRequest.objects.filter(pk=self.stale_request.pk).exists(),
            msg="Expected stale request to be removed, created more than 2 days ago.",
        )
        self.assertFalse(
            EmailChangeRequest.objects.filter(pk=self.completed_request.pk).exists(),
            msg="Expected complete request to be removed.",
        )
        self.assertFalse(
            EmailChangeRequest.objects.filter(
                pk=self.incomplete_recent_request.pk
            ).exists(),
            msg=(
                "Expected incomplete recent request to be removed, created more"
                " than 2 days ago.",
            ),
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_complete_and_stale_email_change_requests.remove_complete_and_stale_email_change_requests",
        return_value=1,
    )
    def test_remove_complete_and_stale_email_change_requests_management_command_dry_run(
        self, mock_remove_complete_and_stale_email_change_requests
    ):
        stdout = io.StringIO()

        call_command(
            "remove_complete_and_stale_email_change_requests",
            dry_run=True,
            stdout=stdout,
        )
        self.assertIn(
            "Removing completed email change requests and requests that have not been"
            " completed within 7 days...",
            stdout.getvalue(),
        )
        self.assertIn(
            "1 completed and/or stale email change request(s) would be removed.",
            stdout.getvalue(),
        )
        mock_remove_complete_and_stale_email_change_requests.assert_called_once_with(
            days=7, dry_run=True
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_complete_and_stale_email_change_requests.remove_complete_and_stale_email_change_requests",
        return_value=1,
    )
    def test_remove_complete_and_stale_email_change_requests_management_command(
        self, mock_remove_complete_and_stale_email_change_requests
    ):
        stdout = io.StringIO()

        call_command("remove_complete_and_stale_email_change_requests", stdout=stdout)
        self.assertIn(
            "Removing completed email change requests and requests that have not been"
            " completed within 7 days...",
            stdout.getvalue(),
        )
        self.assertIn(
            "Successfully removed 1 completed and/or stale email change request(s).",
            stdout.getvalue(),
        )
        mock_remove_complete_and_stale_email_change_requests.assert_called_once_with(
            days=7, dry_run=False
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_complete_and_stale_email_change_requests.remove_complete_and_stale_email_change_requests",
        return_value=2,
    )
    def test_remove_complete_and_stale_email_change_requests_management_command_2_days(
        self, mock_remove_complete_and_stale_email_change_requests
    ):
        stdout = io.StringIO()

        call_command(
            "remove_complete_and_stale_email_change_requests", days=2, stdout=stdout
        )
        self.assertIn(
            "Removing completed email change requests and requests that have not been"
            " completed within 2 days...",
            stdout.getvalue(),
        )
        self.assertIn(
            "Successfully removed 2 completed and/or stale email change request(s).",
            stdout.getvalue(),
        )
        mock_remove_complete_and_stale_email_change_requests.assert_called_once_with(
            days=2, dry_run=False
        )
