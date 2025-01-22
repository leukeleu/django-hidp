from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import TemplateView

from hidp.csp.decorators import hidp_csp_protection


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPOverviewView(TemplateView):
    template_name = "hidp/otp/overview.html"

    def get_context_data(self, **kwargs):
        context = {
            "totp_devices": TOTPDevice.objects.devices_for_user(
                self.request.user, confirmed=True
            ),
            "static_devices": StaticDevice.objects.devices_for_user(
                self.request.user, confirmed=True
            ),
            "back_url": reverse("hidp_account_management:manage_account"),
        }
        return super().get_context_data() | context | kwargs
