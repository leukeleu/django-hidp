import segno

from django_otp import devices_for_user
from django_otp import login as otp_login
from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework.generics import get_object_or_404
from rest_framework.reverse import reverse_lazy

from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.forms import Form
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.views.generic import DetailView, FormView, TemplateView

from hidp.csp.decorators import hidp_csp_protection
from hidp.otp.devices import STATIC_DEVICE_NAME, TOTP_DEVICE_NAME, get_or_create_devices, reset_static_tokens
from hidp.otp.forms import OTPSetupForm
from hidp.rate_limit.decorators import rate_limit_strict

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
            "TOTP_DEVICE_NAME": TOTP_DEVICE_NAME,
            "STATIC_DEVICE_NAME": STATIC_DEVICE_NAME,
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


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPRecoveryCodes(DetailView, FormView):
    """
    View for managing recovery codes.

    This view allows the user to reset their recovery codes.
    """

    template_name = "hidp/otp/recovery_codes.html"
    context_object_name = "device"
    form_class = Form
    success_url = reverse_lazy("hidp_otp_management:recovery-codes")

    def get_object(self, queryset=None):
        return get_object_or_404(
            StaticDevice.objects.devices_for_user(self.request.user)
        )

    def get_context_data(self, **kwargs):
        context = {
            "back_url": reverse("hidp_otp_management:manage"),
        }
        return super().get_context_data() | context | kwargs

    def form_valid(self, form):
        reset_static_tokens(self.get_object())
        return super().form_valid(form)


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_strict, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPSetupDeviceView(FormView):
    """
    View for setting up a new OTP device.

    This view will create a new TOTP and Static device in unconfirmed state for the user
    if they don't already have them. The user must verify the TOTP device by entering a
    valid token and declare that they have saved the recovery codes before the devices
    are confirmed.
    """

    form_class = OTPSetupForm
    success_url = reverse_lazy("hidp_otp_management:manage")
    template_name = "hidp/otp/setup_device.html"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.device = None
        self.user = None

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user
        self.device, self.backup_device = get_or_create_devices(self.user)

        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            {
                "user": self.user,
                "device": self.device,
                "backup_device": self.backup_device,
            }
        )
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context | {
            "title": "Set up Two-Factor Authentication",
            "device": self.device,
            "backup_device": self.backup_device,
            "qrcode": segno.make(self.device.config_url),
            "back_url": reverse("hidp_otp_management:manage"),
        }

    def form_valid(self, form):
        form.save()
        otp_login(self.request, self.device)
        return super().form_valid(form)
