from django.test import RequestFactory, TestCase

from hidp.csp.decorators import hidp_csp_protection


def regular_view(request):
    pass


@hidp_csp_protection
def csp_protected_view(request):
    pass


class TestCSPProtectionDecorator(TestCase):
    client_class = RequestFactory

    def test_regular_view(self):
        request = self.client.get("/")
        regular_view(request)
        self.assertIsNone(getattr(request, "hidp_csp_protection", None))

    def test_hidp_csp_protection_view(self):
        request = self.client.get("/")
        csp_protected_view(request)
        self.assertIsNotNone(getattr(request, "hidp_csp_protection", None))
