from django.conf import settings
from django_otp import user_has_device


def user_needs_to_verify_otp(user):
    """
    This method checks if the device verification is required due to imported
    middleware in the application settings. 
    
    Return True as default, to maintain the current behavior as specified in the 
    otp middleware.

    Returns:
        bool: True if otp verification is required for the user, False otherwise.
    """

    if (
        "hidp.otp.middleware.OTPRequiredMiddleware"
    ) in settings.MIDDLEWARE:
        return True
    
    if (
        "hidp.otp.middleware.OTPSetupRequiredIfStaffUserMiddleware"
    ) in settings.MIDDLEWARE:
        return user.is_staff
    
    if (
        "hidp.otp.middleware.OTPVerificationRequiredIfConfiguredMiddleware"
    ) in settings.MIDDLEWARE:
        return user_has_device(user)
    
    return True
