from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, SimpleTestCase

from hidp.rate_limit.keys import ip_username_rate_limit_key, username_rate_limit_key


class TestUsernameRateLimitKey(SimpleTestCase):
    def test_json_body(self):
        request = RequestFactory().post(
            "/", {"username": "walter@example.com"}, content_type="application/json"
        )
        self.assertEqual(username_rate_limit_key("", request), "walter@example.com")

    def test_form_body(self):
        request = RequestFactory().post("/", {"username": "walter@example.com"})
        self.assertEqual(username_rate_limit_key("", request), "walter@example.com")

    def test_username_is_stripped_and_case_folded(self):
        request = RequestFactory().post(
            "/", {"username": "  Walter@Example.com "}, content_type="application/json"
        )
        self.assertEqual(username_rate_limit_key("", request), "walter@example.com")

    def test_invalid_json_body(self):
        request = RequestFactory().post(
            "/", "{not json", content_type="application/json"
        )
        self.assertEqual(username_rate_limit_key("", request), "")

    def test_json_body_that_is_not_an_object(self):
        request = RequestFactory().post(
            "/", ["walter@example.com"], content_type="application/json"
        )
        self.assertEqual(username_rate_limit_key("", request), "")


class TestIPUsernameRateLimitKey(SimpleTestCase):
    def _key(self, username, *, ip):
        request = RequestFactory().post(
            "/",
            {"username": username},
            content_type="application/json",
            REMOTE_ADDR=ip,
        )
        request.user = AnonymousUser()
        return ip_username_rate_limit_key("", request)

    def test_key_combines_client_and_username(self):
        self.assertEqual(
            self._key(" Walter@Example.com", ip="10.0.0.1"),
            "10.0.0.1:walter@example.com",
        )

    def test_clients_get_different_keys_for_one_username(self):
        self.assertNotEqual(
            self._key("walter@example.com", ip="10.0.0.1"),
            self._key("walter@example.com", ip="10.0.0.2"),
        )
