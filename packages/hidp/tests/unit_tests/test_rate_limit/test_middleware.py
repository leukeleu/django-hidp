from django.test import TestCase, override_settings


@override_settings(ROOT_URLCONF="tests.unit_tests.test_rate_limit.urls")
class TestRateLimitMiddleware(TestCase):
    def test_rate_limited_view(self):
        response = self.client.get("/rate_limited_view/")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.content.decode(),
            (
                "Sorry, you have made too many requests to the server."
                " Please try again later."
            ),
        )

    def test_rate_limited_api_view(self):
        response = self.client.get("/rate_limited_api_view/")
        self.assertEqual(response.status_code, 429)
        self.assertEqual(
            response.json(),
            {
                "detail": (
                    "Sorry, you have made too many requests to the server."
                    " Please try again later."
                )
            },
        )
        self.assertIn("no-store", response["Cache-Control"])
