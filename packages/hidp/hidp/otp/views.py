from django_otp import devices_for_user
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.reverse import reverse_lazy

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import FormView, TemplateView

from hidp.csp.decorators import hidp_csp_protection

from .forms import OTPTokenForm


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


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPDisableView(FormView):
    """
    View to disable OTP for a user.

    This view will delete all OTP devices for a user, effectively disabling OTP for
    that user. Disabling requires the user to be logged in and to provide a valid OTP
    token.
    """

    template_name = "hidp/otp/disable.html"
    form_class = OTPTokenForm
    success_url = reverse_lazy("hidp_otp_management:manage")

    def get_context_data(self, **kwargs):
        context = {
            "back_url": reverse("hidp_otp_management:manage"),
        }
        return super().get_context_data() | context | kwargs

    def get_form_kwargs(self):
        context = {
            "user": self.request.user,
        }
        return super().get_form_kwargs() | context

    @transaction.atomic
    def form_valid(self, form):
        for device in devices_for_user(self.request.user):
            device.delete()
        return super().form_valid(form)
