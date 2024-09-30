from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from hidp.csp.middleware import CSPMiddleware


class TestCSPMiddleware(TestCase):
    client_class = RequestFactory

    def setUp(self):
        self.get_response = mock.Mock(return_value=HttpResponse())
        self.middleware = CSPMiddleware(self.get_response)

    def test_no_csp_if_not_requested(self):
        """Do nothing if `hidp_csp_protection` variable is not set on view."""
        request = self.client.get("/")
        response = self.middleware(request)
        self.assertEqual(
            response,
            self.get_response.return_value,
        )
        self.assertNotIn(
            "Content-Security-Policy",
            response.headers,
        )
        self.assertFalse(hasattr(request, "hidp_csp_nonce"))

    def test_middleware_does_not_override_existing_csp_header(self):
        """Do not override existing CSP header."""
        request = self.client.get("/")
        request.hidp_csp_protection = True

        previous_response = mock.Mock(
            return_value=HttpResponse(headers={"Content-Security-Policy": "existing"})
        )
        middleware = CSPMiddleware(previous_response)

        response = middleware(request)
        self.assertEqual(
            response["Content-Security-Policy"],
            "existing",
        )

    def test_set_csp_header(self):
        """The CSP header is set."""
        request = self.client.get("/")
        request.hidp_csp_protection = True
        response = self.middleware(request)
        self.assertIn(
            "Content-Security-Policy",
            response.headers,
        )
        self.assertTrue(hasattr(request, "hidp_csp_nonce"))

        self.assertIn(
            f"script-src 'nonce-{request.hidp_csp_nonce}' 'strict-dynamic';"
            f" object-src 'none'; base-uri 'none';",
            response.headers["Content-Security-Policy"],
        )
