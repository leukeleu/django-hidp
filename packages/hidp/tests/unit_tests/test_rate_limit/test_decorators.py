from django.test import RequestFactory, TestCase

from hidp.rate_limit.decorators import rate_limit_default, rate_limit_strict


@rate_limit_default
def rate_limit_default_view(request):
    pass


@rate_limit_strict
def rate_limit_strict_view(request):
    pass


class TestRateLimitDecorators(TestCase):
    def test_rate_limit_default(self):
        request = RequestFactory().get("/")
        rate_limit_default_view(request)
        self.assertIsNotNone(getattr(request, "limited", None))

        request = RequestFactory().post("/")
        rate_limit_default_view(request)
        self.assertIsNotNone(getattr(request, "limited", None))

    def test_rate_limit_strict(self):
        request = RequestFactory().get("/")
        rate_limit_strict_view(request)
        self.assertIsNotNone(getattr(request, "limited", None))

        request = RequestFactory().post("/")
        rate_limit_strict_view(request)
        self.assertIsNotNone(getattr(request, "limited", None))
