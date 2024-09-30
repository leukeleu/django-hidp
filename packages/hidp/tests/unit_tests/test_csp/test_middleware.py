from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from hidp.csp.middleware import CSPMiddleware


class TestCSPMiddleware(TestCase):
    client_class = RequestFactory

    def setUp(self):
        self.get_response = mock.Mock(return_value=HttpResponse())
        self.middleware = CSPMiddleware(self.get_response)

    def test_csp_header(self):
        """The CSP header is set."""
        request = self.client.get("/")
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
