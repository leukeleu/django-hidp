# Content Security Policy

HIdP comes with a strict Content Security Policy (CSP) to protect against
cross-site scripting (XSS). If there is already a CSP implementation that sets the CSP
header, this will not be overriden.

In order for the CSP to properly work, make sure  `hidp.csp` is in your INSTALLED_APPS:

```python
INSTALLED_APPS = [
    ...
    # Hello, ID Please
    "hidp.csp",
]
```

## Decorator

The CSP header is set on views that are decorated with the
`hidp.csp.decorators.hidp_csp_protection` decorator and does not have the CSP header
already set.

The decorator also generates a `nonce` that is accessible in the request.

All of HIdP's relevant views have been decorated with this decorator and it is possible
to decorate your own views like this:

```python
from django.utils.decorators import method_decorator

from hidp.csp.decorators import hidp_csp_protection


@method_decorator(hidp_csp_protection, name='dispatch')
class MyCustomView(View):
    def get(self, request):
        ...

```

## Template tag

When you override templates and add scripts and/or styles, they will be blocked by the
CSP by default. In order to allow them, the `nonce` attribute has to be added, which
is available as a template tag; `hidp.csp.templatetags.csp_nonce`.

Example use:

```html
{% load csp_nonce %}
<style nonce="{% csp_nonce %}"></style>

<script nonce="{% csp_nonce %}"></script>
```
