from django.test import TestCase, override_settings

from hidp.config import checks

# This module doubles as the ROOT_URLCONF for these tests
urlpatterns = []


# Simulate a poorly configured Django project
@override_settings(
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "hidp.accounts",
        "tests.custom_user",
    ],
    AUTH_USER_MODEL="auth.User",
    MIDDLEWARE=[],
    USE_TZ=False,
    OAUTH2_PROVIDER=None,
    ROOT_URLCONF=__name__,  # This module is the ROOT_URLCONF
)
class TestConfigChecks(TestCase):
    def test_required_apps_not_installed(self):
        self.assertEqual(
            checks.check_installed_apps(),
            [
                checks.E001,
            ],
            msg="Expected an error because of missing required apps.",
        )

    def test_required_middlewares_not_installed(self):
        self.assertEqual(
            checks.check_middleware(),
            [
                checks.E002,
            ],
        )

    def test_use_tz_not_set(self):
        self.assertEqual(
            checks.check_use_tz(),
            [
                checks.E003,
            ],
        )

    def test_user_model_not_set_correctly(self):
        self.assertEqual(
            checks.check_user_model(),
            [
                checks.E004,
            ],
        )

    def test_oauth2_provider_not_configured(self):
        self.assertEqual(
            checks.check_oauth2_provider(),
            [
                checks.E005,
            ],
        )

    def test_urls_not_configured(self):
        self.assertEqual(
            checks.check_login_url(),
            [
                checks.E006,
            ],
        )

    def test_oidc_provider_apps_not_installed(self):
        self.assertEqual(
            checks.check_oidc_provider_installed_apps(),
            [
                checks.E008,
            ],
        )

    def test_django_otp_installed_but_hidp_otp_not_installed(self):
        self.assertEqual(
            checks.check_hidp_otp_installed_apps_when_django_otp_installed(),
            [
                checks.W001,
            ],
        )

    def test_otp_required_apps_not_installed_not_triggered(self):
        self.assertEqual(
            checks.check_otp_installed_apps(),
            [],
        )

    @override_settings(INSTALLED_APPS=["hidp.otp"])
    def test_otp_required_apps_not_installed(self):
        self.assertEqual(
            checks.check_otp_installed_apps(),
            [
                checks.E009,
            ],
        )

    def test_otp_required_middleware_not_installed_not_triggered(self):
        self.assertEqual(
            checks.check_otp_middleware(),
            [],
        )

    @override_settings(INSTALLED_APPS=["hidp.otp"])
    def test_otp_required_middleware_not_installed(self):
        self.assertEqual(
            checks.check_otp_middleware(),
            [
                checks.E010,
            ],
        )
