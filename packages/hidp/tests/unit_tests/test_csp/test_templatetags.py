from django.template import RequestContext
from django.test import RequestFactory, TestCase

from hidp.csp.templatetags.csp_nonce import csp_nonce


class TestCSPNonceTemplatetag(TestCase):
    client_class = RequestFactory

    def test_hidp_csp_nonce(self):
        """The templatetag returns the nonce."""
        request = self.client.get("/")
        request.hidp_csp_nonce = "nonce"
        context = RequestContext(request)

        self.assertEqual(csp_nonce(context), "nonce")

    def test_no_nonce(self):
        """No nonce."""
        request = self.client.get("/")
        context = RequestContext(request)
        self.assertIsNone(csp_nonce(context))
