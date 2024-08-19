# Configure as OIDC Provider

To configure HIdP as an OIDC Provider, please make sure you followed all the steps in
[Installation](project:./installation.md) and you have created a superuser.

:::{note}
The OIDC Provider part of HIdP is based on [Django OAuth Toolkit](https://django-oauth-toolkit.readthedocs.io/en/latest/)
:::

## Add Application

Add the Django Admin to the urls of your HIdP app:

```python
from django.contrib import admin
from django.urls import include, path
from hidp.config import urls as hidp_urls

urlpatterns = [
    ...,
    path("", include(hidp_urls)),
    path("django-admin/", admin.site.urls),
    ...,
]
```

Log in to the Django admin of the HIdP app and add an application under
'Django OAuth Toolkit' with the following fields:

- **Client id**: A unique id to connect your OIDC Client with. This ID is also visible
to end users in URLs
- **Redirect uris**: At least one redirection endpoint where the server will redirect
to after authorization. This URL must also be provided by the OIDC client
for verification. For example, https://www.yourdomain.dev/_/oidc/callback/
- **Client type**: Public
- **Authorization grant type**: Authorization code
- **Skip authorization**: Yes (for trusted clients)
- **Algorithm**: RSA with SHA-2 256

:::{important}
Save the generated **Client secret** somewhere safe before saving the form, because the
secret will be hashed when you save the form.
:::

:::{note}
PKCE is required by default.
:::

## Provided URLs

### `/o/authorize`
[AuthorizationView](https://django-oauth-toolkit.readthedocs.io/en/latest/views/details.html#oauth2_provider.views.base.AuthorizationView)

### `/o/token/`
[TokenView](https://django-oauth-toolkit.readthedocs.io/en/latest/views/details.html#oauth2_provider.views.base.TokenView)

### `/o/userinfo/`
This view provides extra user details

### `/o/.well-known/jwks.json`
This view provides details of the keys used to sign the JWTs generated for ID tokens,
so that clients are able to verify them.
