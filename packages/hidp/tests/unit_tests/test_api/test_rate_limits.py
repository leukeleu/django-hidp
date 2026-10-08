from http import HTTPStatus
from unittest import mock

from django_ratelimit.core import ALL
from rest_framework.test import APITestCase

from django.core.cache import cache
from django.test import override_settings
from django.urls import reverse

from hidp.test.factories import user_factories

from .test_otp import confirmed_devices


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
)
class RateLimitTestCase(APITestCase):
    def setUp(self):
        cache.clear()


# Leaves only the per-username limit, which the per-IP limits would otherwise mask.
@mock.patch("hidp.rate_limit.decorators._STRICT_RATE_LIMITS", [])
class TestLoginRateLimit(RateLimitTestCase):
    """Login attempts are limited per username and client, with a JSON 429."""

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:login")

    def _login(self, username, *, ip="10.0.0.1"):
        return self.client.post(
            self.url,
            {"username": username, "password": "wrong"},
            format="json",
            REMOTE_ADDR=ip,
        )

    def _exhaust_limit(self, username, *, ip="10.0.0.1"):
        for _ in range(10):
            self._login(username, ip=ip)

    def test_rate_limited_response_is_json_and_never_cached(self):
        self._exhaust_limit("walter@example.com")

        response = self._login("walter@example.com")

        self.assertEqual(response.status_code, HTTPStatus.TOO_MANY_REQUESTS)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("detail", response.json())
        self.assertIn("no-store", response["Cache-Control"])

    def test_padded_and_recased_usernames_share_the_limit(self):
        self._exhaust_limit("walter@example.com")

        response = self._login("  Walter@Example.com ")

        self.assertEqual(response.status_code, HTTPStatus.TOO_MANY_REQUESTS)

    def test_limit_is_per_username(self):
        self._exhaust_limit("walter@example.com")

        response = self._login("jesse@example.com")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_limit_is_per_client(self):
        # One client guessing a password must not lock the owner out.
        self._exhaust_limit("walter@example.com", ip="10.0.0.1")

        response = self._login("walter@example.com", ip="10.0.0.2")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_many_attempts_across_clients_require_i_am_not_a_robot(self):
        """Like the HTML login, a username tried from many IPs needs the checkbox."""
        for ip in range(10):
            self._login("walter@example.com", ip=f"10.0.1.{ip}")

        response = self._login("walter@example.com", ip="10.0.2.1")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("i_am_not_a_robot", response.json())

    def test_i_am_not_a_robot_accepts_the_login(self):
        user = user_factories.VerifiedUserFactory(email="walter@example.com")
        for ip in range(10):
            self._login(user.email, ip=f"10.0.1.{ip}")

        response = self.client.post(
            self.url,
            {
                "username": user.email,
                "password": "P@ssw0rd!",
                "i_am_not_a_robot": True,
            },
            format="json",
            REMOTE_ADDR="10.0.2.1",
        )

        self.assertEqual(response.status_code, HTTPStatus.OK, response.json())

    def test_other_usernames_need_no_i_am_not_a_robot(self):
        for ip in range(10):
            self._login("walter@example.com", ip=f"10.0.1.{ip}")

        response = self._login("jesse@example.com", ip="10.0.2.1")

        self.assertNotIn("i_am_not_a_robot", response.json())


# The limit under test is not the first, which django-ratelimit names differently.
TWO_RATE_LIMITS = [("ip", ALL, "100/s"), ("ip", ALL, "3/m")]


@mock.patch("hidp.rate_limit.decorators._DEFAULT_RATE_LIMITS", TWO_RATE_LIMITS)
@mock.patch("hidp.rate_limit.decorators._STRICT_RATE_LIMITS", TWO_RATE_LIMITS)
class TestRateLimitGroups(RateLimitTestCase):
    """Every API view has a budget of its own, unless it shares a group."""

    def test_exhausting_one_view_does_not_limit_another(self):
        resend_url = reverse("hidp_api:email_verification_resend")
        for _ in range(3):
            self.client.post(resend_url)
        self.assertEqual(
            self.client.post(resend_url).status_code, HTTPStatus.TOO_MANY_REQUESTS
        )

        response = self.client.post(
            reverse("hidp_api:login"),
            {"username": "walter@example.com", "password": "wrong"},
            format="json",
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)

    def test_otp_codes_and_recovery_codes_share_a_budget(self):
        user = user_factories.VerifiedUserFactory()
        self.client.force_login(user)
        confirmed_devices(user)
        for _ in range(3):
            self.client.post(reverse("hidp_api:otp_verify"), {"otp_token": "000000"})

        response = self.client.post(
            reverse("hidp_api:otp_verify_recovery_code"), {"recovery_code": "x"}
        )

        self.assertEqual(response.status_code, HTTPStatus.TOO_MANY_REQUESTS)

    def test_regenerating_recovery_codes_is_limited(self):
        user = user_factories.VerifiedUserFactory()
        self.client.force_login(user)
        confirmed_devices(user)
        url = reverse("hidp_api:otp_recovery_codes")
        for _ in range(3):
            self.client.post(url)

        self.assertEqual(
            self.client.post(url).status_code, HTTPStatus.TOO_MANY_REQUESTS
        )
