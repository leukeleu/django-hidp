from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from hidp.csp.decorators import hidp_csp_protection


def regular_view(request):
    return HttpResponse("Regular view")


@hidp_csp_protection
def csp_protected_view(request):
    return HttpResponse("Protected view")


@hidp_csp_protection
def csp_protected_view_with_existing_csp(request):
    return HttpResponse(
        "Protected view with existing CSP",
        headers={"Content-Security-Policy": "existing"},
    )


class TestCSPProtectionDecorator(TestCase):
    client_class = RequestFactory

    def test_regular_view(self):
        request = self.client.get("/")
        response = regular_view(request)
        self.assertFalse(
            "Content-Security-Policy" in response.headers,
            msg="CSP header should not be present for regular views.",
        )

    def test_hidp_csp_protection_view(self):
        request = self.client.get("/")
        response = csp_protected_view(request)
        self.assertTrue(
            "Content-Security-Policy" in response.headers,
            msg="CSP header should be present for decorated views.",
        )

    def test_does_not_override_existing_csp_header(self):
        request = self.client.get("/")
        response = csp_protected_view_with_existing_csp(request)
        self.assertEqual(
            response.headers["Content-Security-Policy"],
            "existing",
            msg="CSP header should not be overridden.",
        )
