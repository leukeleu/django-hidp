from django.test import RequestFactory, TestCase

from hidp.csp.context_processors import hidp_csp_nonce


class TestCSPContextProcessor(TestCase):
    client_class = RequestFactory

    def test_hidp_csp_nonce(self):
        """The context processor returns the nonce."""
        request = self.client.get("/")
        request.hidp_csp_nonce = "nonce"
        self.assertEqual(hidp_csp_nonce(request), {"hidp_csp_nonce": "nonce"})

    def test_no_nonce(self):
        """No nonce."""
        self.assertEqual(hidp_csp_nonce(self.client.get("/")), {"hidp_csp_nonce": None})
