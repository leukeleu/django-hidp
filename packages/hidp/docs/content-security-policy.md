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

The middleware generates a nonce and sets the Content Security Policy header. The
context processor makes the nonce available in all templates.

In your templates, script and style tags will be blocked by the CSP by default. In order
to allow them, they need to have the "nonce" attribute set to `hidp_csp_nonce`:

```html
<style nonce="{{ hidp_csp_nonce }}"></style>

<script nonce="{{ hidp_csp_nonce }}"></script>
```



