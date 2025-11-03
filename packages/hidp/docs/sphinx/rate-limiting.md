# Rate limiting

HIdP uses the [django-ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html)
package to apply rate limiting on key pages, such as the login and registration pages,
to prevent DDoS and brute force attacks.

## Default rate limits

The default rate limits are:

- 10 requests per second
- 30 requests per minute

The following rate limit is added for views that need to be more strict:

- 100 requests per 15 minutes

The time component of each rate limit also serves as the 'lockout period'. Meaning
requests from the same IP will be blocked for this duration when they exceed the limit.

HIdP may be used by applications with many users sharing the same IP, such as schools
or corporate networks. Since rate limiting is based on IP, lowering the default limits
could be disruptive. However, you can adjust the rate limits to be more strict
if needed.

## Login page "soft" rate limit

The login page has an additional rate limit to prevent too many login attempts
using the same username within a short period of time. This rate limit is
**not** tied to the incomming IP address, allowing it to catch
distributed attacks.

Once triggered, it does **not** block subsequent requests to avoid locking
legitimate users out of their accounts.

Instead, when the rate limit is exceeded, the login form is replaced with the
`RateLimitedAuthenticationForm`. This forms requires the user to check a box
to prove they are not a robot before logging in.

This measure is relatively easy to bypass, so it is recommended to override
the `hidp.accounts.views.LoginView` and configure a custom `rate_limited_form_class`
that implements a more robust countermeasure.

## Adding your own rate limits

You can add additional rate limits to views like this:

```python
from django.utils.decorators import method_decorator

from django_ratelimit.decorators import ratelimit

from hidp.accounts.views import LoginView

@method_decorator(ratelimit(key='ip', rate='1/m', method=ratelimit.UNSAFE), name='dispatch')
class MyCustomLoginView(LoginView):
    def get(self, request):
        ...

```

:::{note}
For more examples, see [django-ratelimit documentation](https://django-ratelimit.readthedocs.io/en/stable/usage.html).
:::

## Security considerations

HIdP uses `ip` as the [ratelimit key](https://django-ratelimit.readthedocs.io/en/stable/keys.html#ratelimit-keys)
for most rate limits. To ensure safety, it is crucial to that `REMOTE_ADDR` is resolved
correctly, especially when Django is behind a load balancer or reverse proxy.

If `REMOTE_ADDR` is not resolved correctly, the rate limits may be applied to all
requests indiscriminately, regardless of the actual IP address, or could be
bypassed entirely.

Without a proper cache setup the rate limits will not be applied correctly either, see [Cache](project:installation.md#cache) for more information.

:::{note}
For more information, see [django-ratelimit security considerations](https://django-ratelimit.readthedocs.io/en/stable/security.html#security-considerations).
:::

When configured correctly, HIdP's rate limits offer basic protection against brute
force attacks and other bot behavior. However, while rate limits help mitigate some
risks, they are not a comprehensive security solution. Consider combining rate limits
with other security measures, such as CAPTCHAs, and continuously monitoring for
potential threats.
