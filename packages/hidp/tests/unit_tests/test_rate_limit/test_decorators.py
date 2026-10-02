from unittest import mock

from django_ratelimit.core import ALL
from django_ratelimit.exceptions import Ratelimited

from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.utils.decorators import method_decorator
from django.views import View

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


# Test the second limit: django-ratelimit only names the group of the first limit
# after the view class.
TWO_RATE_LIMITS = [("ip", ALL, "100/s"), ("ip", ALL, "3/m")]


@method_decorator(rate_limit_default, name="dispatch")
class RateLimitedView(View):
    def post(self, request):
        return HttpResponse()


class OtherRateLimitedView(RateLimitedView):
    pass


class GroupedRateLimitedView(RateLimitedView):
    rate_limit_group = "shared"


class OtherGroupedRateLimitedView(RateLimitedView):
    rate_limit_group = "shared"


class PlainView(View):
    def post(self, request):
        return HttpResponse()


class OtherPlainView(PlainView):
    pass


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
)
@mock.patch("hidp.rate_limit.decorators._DEFAULT_RATE_LIMITS", TWO_RATE_LIMITS)
class TestRateLimitGroups(TestCase):
    """Each class-based view counts its requests in a group of its own."""

    def setUp(self):
        cache.clear()
        self.request = RequestFactory().post("/", REMOTE_ADDR="10.0.0.1")

    def _exhaust(self, view):
        for _ in range(3):
            view(self.request)
        with self.assertRaises(Ratelimited):
            view(self.request)

    def test_views_do_not_share_a_budget(self):
        self._exhaust(RateLimitedView.as_view())

        response = OtherRateLimitedView.as_view()(self.request)

        self.assertEqual(response.status_code, 200)

    def test_views_with_the_same_group_share_a_budget(self):
        self._exhaust(GroupedRateLimitedView.as_view())

        with self.assertRaises(Ratelimited):
            OtherGroupedRateLimitedView.as_view()(self.request)

    def test_as_view_functions_do_not_share_a_budget(self):
        self._exhaust(rate_limit_default(PlainView.as_view()))

        response = rate_limit_default(OtherPlainView.as_view())(self.request)

        self.assertEqual(response.status_code, 200)
