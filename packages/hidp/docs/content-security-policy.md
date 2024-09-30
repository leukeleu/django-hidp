# Content Security Policy

HIdP comes with a strict Content Security Policy (CSP) to protect against
cross-site scripting (XSS). In case there is already a CSP implementation, it is
possible to silence the system check.

In order for the CSP to properly work, these settings need to be present in your Django
settings.

```python
MIDDLEWARE = [
    ...,
    "hidp.csp.middleware.CSPMiddleware",
    ...,
]
...

TEMPLATES = [
    {
        ...,
        "OPTIONS": {
            "context_processors": [
                ...,
                "hidp.csp.context_processors.hidp_csp_nonce",
                ...,
            ],
        },
    },
]
```

:::{note}
The middleware order does not matter unless you have other middleware modifying the
CSP header.
:::

The middleware generates a nonce and sets the Content Security Policy header to all
HIdP views. The context processor makes the nonce available in all templates in the
`hidp_csp_nonce` variable.

When you override templates and add scripts and/or styles, they will be blocked by the
CSP, unless you set the `nonce` attribute:

```html
<style nonce="{{ hidp_csp_nonce }}"></style>

<script nonce="{{ hidp_csp_nonce }}"></script>
```

It is also possible to add the same CSP to your own views by decorating the views with
the `hidp.csp.decorators.hidp_csp_protection` decorator:

```python
from django.utils.decorators import method_decorator

from hidp.csp.decorators import hidp_csp_protection


@method_decorator(hidp_csp_protection, name='dispatch')
class MyCustomView(View):
    def get(self, request):
        ...

```
