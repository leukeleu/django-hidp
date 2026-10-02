from http import HTTPStatus
from unittest import mock

from django_otp.oath import totp
from rest_framework.test import APITestCase

from django.conf import settings
from django.core import mail
from django.db import connection
from django.test import modify_settings, override_settings
from django.urls import reverse

from hidp.otp.devices import get_or_create_devices
from hidp.test.factories import user_factories

OTP_REQUIRED = modify_settings(
    MIDDLEWARE={"append": "hidp.otp.middleware.OTPRequiredMiddleware"}
)


def current_token(device):
    token = totp(device.bin_key, step=device.step, t0=device.t0, digits=device.digits)
    return f"{token:0{device.digits}d}"


def confirmed_devices(user):
    device, backup_device = get_or_create_devices(user)
    device.confirmed = backup_device.confirmed = True
    device.save()
    backup_device.save()
    return device, backup_device


@OTP_REQUIRED
class TestOTPAuthState(APITestCase):
    """A logged-in user who must verify OTP is only partly authenticated."""

    def setUp(self):
        self.user = user_factories.VerifiedUserFactory()
        self.client.force_login(self.user)

    def test_login_responds_with_pending_step(self):
        self.client.logout()

        response = self.client.post(
            reverse("hidp_api:login"),
            {"username": self.user.email, "password": "P@ssw0rd!"},
        )

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "otp_setup"}]}
        )

    def test_pending_setup(self):
        response = self.client.get(reverse("hidp_api:session"))

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "otp_setup"}]}
        )

    def test_pending_verify(self):
        confirmed_devices(self.user)

        response = self.client.get(reverse("hidp_api:session"))

        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "otp_verify"}]}
        )

    def test_protected_api_view_responds_with_auth_state(self):
        confirmed_devices(self.user)

        response = self.client.get(reverse("hidp_api:user"))

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "otp_verify"}]}
        )
        self.assertIn("no-store", response["Cache-Control"])

    def test_html_view_redirects_to_html_verify_view(self):
        confirmed_devices(self.user)

        response = self.client.get(reverse("hidp_account_management:manage_account"))

        self.assertRedirects(
            response,
            f"{reverse('hidp_otp:verify')}?next=%2Fmanage%2F",
            fetch_redirect_response=False,
        )

    def _assert_html_view_redirects_to(self, expected_url, **frontend_urls):
        with override_settings(
            HIDP_FRONTEND_URLS=settings.HIDP_FRONTEND_URLS | frontend_urls
        ):
            response = self.client.get(
                reverse("hidp_account_management:manage_account")
            )

        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    def test_html_view_redirects_to_frontend(self):
        confirmed_devices(self.user)

        self._assert_html_view_redirects_to(
            "http://testserver/frontend/otp/verify/?next=%2Fmanage%2F",
            otp_verify="/frontend/otp/verify/",
        )

    def test_frontend_redirect_keeps_the_query_of_the_template(self):
        confirmed_devices(self.user)

        self._assert_html_view_redirects_to(
            "http://testserver/frontend/otp/verify/?lang=nl&next=%2Fmanage%2F",
            otp_verify="/frontend/otp/verify/?lang=nl",
        )

    def test_html_view_redirects_to_frontend_setup(self):
        self._assert_html_view_redirects_to(
            "http://testserver/frontend/otp/setup/?next=%2Fmanage%2F",
            otp_setup="/frontend/otp/setup/",
        )

    def test_protected_endpoints_need_verification(self):
        confirmed_devices(self.user)
        endpoints = [
            ("get", "hidp_api:user"),
            ("patch", "hidp_api:user"),
            ("get", "hidp_api:otp"),
            ("get", "hidp_api:otp_recovery_codes"),
            ("post", "hidp_api:otp_recovery_codes"),
            ("post", "hidp_api:otp_disable"),
            ("post", "hidp_api:otp_disable_recovery_code"),
            ("get", "hidp_api:email_change"),
            ("post", "hidp_api:email_change"),
            ("delete", "hidp_api:email_change"),
            ("post", "hidp_api:email_change_confirm"),
            ("post", "hidp_api:password_change"),
            ("post", "hidp_api:set_password"),
        ]
        for method, url_name in endpoints:
            with self.subTest(method=method, url_name=url_name):
                response = getattr(self.client, method)(reverse(url_name))
                self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
                self.assertEqual(response.json()["pending"], [{"step": "otp_verify"}])

    def test_verify(self):
        device, _backup_device = confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_verify"), {"otp_token": current_token(device)}
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json()["user"]["id"], str(self.user.id))
        self.assertEqual(response.json()["pending"], [])

    def test_verify_cycles_the_session_key(self):
        device, _backup_device = confirmed_devices(self.user)
        session_key = self.client.session.session_key

        self.client.post(
            reverse("hidp_api:otp_verify"), {"otp_token": current_token(device)}
        )

        self.assertNotEqual(self.client.session.session_key, session_key)
        self.assertEqual(
            self.client.get(reverse("hidp_api:session")).status_code, HTTPStatus.OK
        )

    def test_verify_invalid_token(self):
        confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_verify"), {"otp_token": "000000"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("non_field_errors", response.json())

    def test_verify_without_device(self):
        response = self.client.post(
            reverse("hidp_api:otp_verify"), {"otp_token": "000000"}
        )

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "otp_not_configured")

    def test_verify_recovery_code(self):
        _device, backup_device = confirmed_devices(self.user)
        code = backup_device.token_set.first().token

        response = self.client.post(
            reverse("hidp_api:otp_verify_recovery_code"), {"recovery_code": code}
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertFalse(backup_device.token_set.filter(token=code).exists())
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("http://testserver/frontend/otp/", mail.outbox[0].body)


@modify_settings(
    MIDDLEWARE={
        "append": [
            "hidp.otp.middleware.OTPVerificationRequiredIfConfiguredMiddleware",
            "hidp.otp.middleware.OTPSetupRequiredIfStaffUserMiddleware",
        ]
    }
)
class TestSeveralOTPPolicies(APITestCase):
    """The auth state reports a step whenever any OTP policy requires one."""

    def test_second_policy_requires_setup(self):
        user = user_factories.VerifiedUserFactory(is_staff=True)
        self.client.force_login(user)

        response = self.client.get(reverse("hidp_api:session"))

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(
            response.json(), {"user": None, "pending": [{"step": "otp_setup"}]}
        )


@OTP_REQUIRED
class TestOTPSetupView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:otp_setup")

    def setUp(self):
        self.user = user_factories.VerifiedUserFactory()
        self.client.force_login(self.user)

    def test_get_is_stable(self):
        first = self.client.get(self.url).json()
        second = self.client.get(self.url).json()

        self.assertEqual(first, second)
        self.assertEqual(
            set(first), {"secret", "config_url", "qr_code", "recovery_codes"}
        )
        self.assertEqual(len(first["recovery_codes"]), 10)
        self.assertTrue(first["qr_code"].startswith("data:image/svg+xml"))

    def test_secret_is_not_cached(self):
        response = self.client.get(self.url)

        self.assertIn("no-store", response["Cache-Control"])

    def test_confirm(self):
        self.client.get(self.url)
        device = self.user.totpdevice_set.get()

        response = self.client.post(
            self.url,
            {"otp_token": current_token(device), "confirm_stored_backup_tokens": True},
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json()["pending"], [])
        device.refresh_from_db()
        self.assertTrue(device.confirmed)
        self.assertEqual(len(mail.outbox), 1)

    def test_confirm_cycles_the_session_key(self):
        self.client.get(self.url)
        device = self.user.totpdevice_set.get()
        session_key = self.client.session.session_key

        self.client.post(
            self.url,
            {"otp_token": current_token(device), "confirm_stored_backup_tokens": True},
        )

        self.assertNotEqual(self.client.session.session_key, session_key)

    def test_confirm_requires_stored_recovery_codes(self):
        self.client.get(self.url)
        device = self.user.totpdevice_set.get()

        response = self.client.post(
            self.url,
            {"otp_token": current_token(device), "confirm_stored_backup_tokens": False},
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("confirm_stored_backup_tokens", response.json())

    def test_only_recovery_codes_need_verification_first(self):
        confirmed_devices(self.user)
        self.user.totpdevice_set.all().delete()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "otp_verification_required")
        self.assertNotIn("recovery_codes", response.json())

    def test_only_recovery_codes_after_verification(self):
        _device, backup_device = confirmed_devices(self.user)
        self.user.totpdevice_set.all().delete()
        self.client.post(
            reverse("hidp_api:otp_verify_recovery_code"),
            {"recovery_code": backup_device.token_set.first().token},
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.OK)

    def test_already_configured(self):
        confirmed_devices(self.user)

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "otp_already_configured")


class TestOTPManagement(APITestCase):
    """Managing OTP needs a verified session when a device is configured."""

    def setUp(self):
        self.user = user_factories.VerifiedUserFactory()
        self.client.force_login(self.user)

    def test_status_not_configured(self):
        response = self.client.get(reverse("hidp_api:otp"))

        self.assertEqual(
            response.json(), {"configured": False, "recovery_codes_remaining": None}
        )

    def test_status_configured(self):
        confirmed_devices(self.user)

        response = self.client.get(reverse("hidp_api:otp"))

        self.assertEqual(
            response.json(), {"configured": True, "recovery_codes_remaining": 10}
        )

    def test_regenerate_recovery_codes(self):
        _device, backup_device = confirmed_devices(self.user)
        old_codes = set(backup_device.token_set.values_list("token", flat=True))

        response = self.client.post(reverse("hidp_api:otp_recovery_codes"))

        new_codes = set(response.json()["recovery_codes"])
        self.assertEqual(len(new_codes), 10)
        self.assertFalse(old_codes & new_codes)
        self.assertEqual(len(mail.outbox), 1)

    def test_recovery_codes_are_not_cached(self):
        confirmed_devices(self.user)

        response = self.client.get(reverse("hidp_api:otp_recovery_codes"))

        self.assertIn("no-store", response["Cache-Control"])

    def test_recovery_codes_without_device(self):
        response = self.client.get(reverse("hidp_api:otp_recovery_codes"))

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_disable(self):
        device, _backup_device = confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_disable"), {"otp_token": current_token(device)}
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertFalse(self.user.totpdevice_set.exists())
        self.assertFalse(self.user.staticdevice_set.exists())

    def test_disable_with_recovery_code(self):
        _device, backup_device = confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_disable_recovery_code"),
            {"recovery_code": backup_device.token_set.first().token},
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertFalse(self.user.totpdevice_set.exists())

    def test_disable_invalid_token(self):
        confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_disable"), {"otp_token": "000000"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertTrue(self.user.totpdevice_set.exists())

    @OTP_REQUIRED
    def test_unverified_session_cannot_disable(self):
        device, _backup_device = confirmed_devices(self.user)

        response = self.client.post(
            reverse("hidp_api:otp_disable"), {"otp_token": current_token(device)}
        )

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertTrue(self.user.totpdevice_set.exists())


class TestOTPUnderAtomicRequests(APITestCase):
    """A rejected code still counts towards the throttle of the device."""

    def test_failed_verification_is_throttled(self):
        user = user_factories.VerifiedUserFactory()
        self.client.force_login(user)
        device, _backup_device = confirmed_devices(user)

        with mock.patch.dict(connection.settings_dict, {"ATOMIC_REQUESTS": True}):
            response = self.client.post(
                reverse("hidp_api:otp_verify"), {"otp_token": "000000"}
            )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        device.refresh_from_db()
        self.assertEqual(device.throttling_failure_count, 1)
