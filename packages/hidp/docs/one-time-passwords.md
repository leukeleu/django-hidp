# One-time Passwords (OTP)

The `otp` extra provides support for one-time passwords (OTP) in HIdP. This allows users 
to enable two-factor authentication (2FA) for their accounts.

:::{note}
OTP support in HIdP is based on [django-otp](https://django-otp-official.readthedocs.io/en/stable/).
:::

## Installation

OTP support in HIdP is included in the `recommended` extra. To install the `recommended` extra, use the following 
command:

```shell
pip install django-hidp[recommended]
```

See [Installation Extras](installation-extras.md) for more information on available extras.

## Configuration

To enable OTP support in HIdP, the following needs to be added to the Django settings:

```python
INSTALLED_APPS = [
    ...,
    'django_otp',
    'django_otp.plugins.otp_totp',
    'django_otp.plugins.otp_static',
    'hidp.otp',
    ...
]

MIDDLEWARE = [
    ...,
    # Add the OTP middleware to the middleware list, after 
    # the session and authentication middleware
    'django_otp.middleware.OTPMiddleware',
]
```

:::{important}
The configuration above does not enable OTP verification on login just yet. Read the following sections to learn how to
enable OTP verification for users.
:::


## Usage

After enabling OTP support in HIdP, users can enable two-factor authentication (2FA) for their accounts. Whether users
are required to verify or enable 2FA can be configured by enabling one or more OTP Policies.

OTP Policies are used to configure the requirements for OTP verification. Site-wide policies are implemented as Django
middleware, while view decorators can be used to apply policies to specific views.

:::{note}
These sections use the same terminology as the Django-OTP documentation. For more details, refer to the
[Django-OTP glossary](https://django-otp-official.readthedocs.io/en/stable/overview.html#glossary).
:::

## Available OTP Policies

### Site-wide Policies

The following site-wide OTP policies are available. To enable a policy, add the middleware to the `MIDDLEWARE` list in
the Django settings, **after** the `django_otp.middleware.OTPMiddleware` middleware.

`hidp.otp.middleware.OTPRequiredMiddleware`
: Requires users to verify their OTP before accessing any view (that is not exempt using the 
  [`otp_exempt`](#view-decorators) decorator). This is the strictest policy: users must verify their OTP before they 
  can access any part of the site, which also means that if they haven't set up OTP yet, they will be redirected to the
  OTP setup view upon first login.

`hidp.otp.middleware.OTPVerificationRequiredIfConfiguredMiddleware`
: Requires users to verify their OTP _if_ they have configured OTP. This policy is less strict than `OTPRequiredMiddleware`
  because it allows users to access the site without verifying their OTP if they haven't configured OTP yet.

`hidp.otp.middleware.OTPSetupRequiredIfStaffUserMiddleware`
: Requires staff users to set up and verify their OTP before accessing any view. This policy is useful for enforcing OTP
  setup for staff users, while allowing non-staff users to access the site without setting up OTP.

  :::{warning}
  This policy does not enforce _other_ users that have OTP set up are required to verify their OTP. Also add
  `OTPVerificationRequiredIfConfigured` middleware in order to do so.
  :::

### View Decorators

The following view decorators can be used to apply OTP policies to specific views:

`django_otp.decorators.otp_required`
: Requires users to verify their OTP before accessing the view. See the
  [Django-OTP documentation](https://django-otp-official.readthedocs.io/en/stable/auth.html#django_otp.decorators.otp_required)
  for more information.

`hipd.otp.decorators.otp_exempt`
: Exempts users from verifying their OTP when accessing the view, even if a site-wide policy (middleware) requires OTP
  verification.


## Examples

You can combine multiple policies by adding multiple middleware classes to the `MIDDLEWARE` list in the Django settings.
For example, to make OTP required for staff users and optional for non-staff users, you can use the following configuration:

```python
MIDDLEWARE = [
    ...,
    'django_otp.middleware.OTPMiddleware',
    'hidp.otp.middleware.OTPSetupRequiredIfStaffUserMiddleware',
    'hidp.otp.middleware.OTPVerificationRequiredIfConfiguredMiddleware',
    ...
]
```

If you have certain views that should be exempt from OTP verification, you can use the `otp_exempt` decorator:

```python
from hidp.otp.decorators import otp_exempt

@otp_exempt
def my_view(request):
    # This view can be accessed without verifying OTP  
    ...


# Or, on a class-based view:
from django.utils.decorators import method_decorator
from django.views.generic import View

@method_decorator(otp_exempt, name='dispatch')
class MyView(View):
    ...
```


## Customizing OTP Policies

You can create custom OTP policies by subclassing the `hidp.otp.middleware.OTPMiddlewareBase` class and implementing the
`user_needs_verification` method. This method should return `True` if the user needs to verify their OTP, and `False`
otherwise. The method may assume the user is authenticated and not yet verified.

For example, to create a policy that requires OTP verification for users with a specific group, you can create a custom
middleware class like this:

```python
from hidp.otp.middleware import OTPMiddlewareBase

class OTPRequiredForGroupMiddleware(OTPMiddlewareBase):
    def user_needs_verification(self, user):
        return user.groups.filter(name='RequireOTP').exists()
```

See the source code of the `hidp.otp.middleware` module for more examples of custom OTP policies.


```{eval-rst}
.. autoclass:: hidp.otp.middleware.OTPMiddlewareBase
  :members:
```
