# Configure OIDC Clients

In addition to traditional username and password authentication,
HIdP supports authentication using OpenID Connect (OIDC).

HIdP has built-in support for both Google and Microsoft as OIDC providers,
and can be extended to support others.

## Quick Start

To enable OIDC authentication, you need to configure the OIDC clients in your Django settings.

```python
from hidp import config as hidp_config

from hidp.federated.providers.google import GoogleOIDCClient
from hidp.federated.providers.microsoft import MicrosoftOIDCClient

hidp_config.configure_oidc_clients(
    GoogleOIDCClient(client_id="your-client-id", client_secret="****"),
    MicrosoftOIDCClient(client_id="your-client-id"),
)
```

:::{important}
Never expose a client secret in the source code or client-side code. Use environment
variables or a secret management tool to store the client secret.
:::

:::{note}
It is strongly recommended to run the `refresh_oidc_clients_jwks` management command
after each deploy and at least once a day to ensure the JWKs are up to date.

See the documentation on [refreshing OIDC clients JWKs](project:management-commands.md#refresh_oidc_clients_jwks)
for more information.
:::

## Obtaining Client Credentials

To use Google and/or Microsoft as an OIDC provider, you'll need to create a "project" in
their respective online portals and configure the client with the correct credentials in HIdP.

### Google

Follow the instructions from Google on how to set up OpenID Connect on
the [Google Identity Platform](https://developers.google.com/identity/openid-connect/openid-connect).

Quick start:

1. Create a new project in the [Google Cloud Console](https://console.cloud.google.com/projectcreate),
   and make sure to select it as the active project. Skip this step if you already
   have a project.

2. Configure the [OAuth consent screen](https://console.cloud.google.com/apis/credentials/consent).
   This is required for the OAuth 2.0 flow. It is not possible to obtain OAuth 2.0
   credentials without configuring this.

:::{note}
Uploading a logo will require verification of the application. Avoid uploading a logo
if you are creating a test application.
:::

:::{note}
App domains and authorized domains are not required for testing. They can be left empty.
:::

3. [Obtain OAuth 2.0 credentials](https://console.cloud.google.com/apis/credentials/oauthclient)

   - Select "Web application" as the application type.
   - Configure the authorized redirect URI:

     `https://<domain>/login/oidc/callback/google/`

     Note: The redirect URI must be a valid *public* URL or localhost.
     For development use either localhost or a hosts file entry to
     map a public domain to a local development server.

:::{tip}
Use `local.<production-domain>` to avoid squatting on a real domain.
:::

  - Save the client ID and client secret, they will be required for the
    OpenID Connect client configuration.

In your Django settings, add the following:

```python
from hidp import config as hidp_config
from hidp.federated.providers.google import GoogleOIDCClient

hidp_config.configure_oidc_clients(
    GoogleOIDCClient(client_id="your-client-id", client_secret="****"),
)
```

:::{important}
Never expose the client secret in the source code or client-side code. Use environment
variables or a secret management tool to store the client secret.
:::

### Microsoft

Follow the instructions from Microsoft on how to set up OpenID Connect on the
[Microsoft Identity Platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).

Quick start:

1. Register a new application in the [Entra portal](https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade/quickStartType~/null/sourceType/Microsoft_AAD_IAM)

   - Set the application type to "Single Page Application".
     This enables the Code Flow with PKCE, and avoids the need for a client secret.
   - Pick the broadest account type possible (organization, personal, etc.)
   - Set the redirect URI to: https://<domain>/login/oidc/callback/microsoft/
     Private domains (e.g. *.local, *.test) are allowed.

In your Django settings, add the following:

```python
from hidp import config as hidp_config
from hidp.federated.providers.microsoft import MicrosoftOIDCClient

hidp_config.configure_oidc_clients(
    MicrosoftOIDCClient(client_id="your-client-id"),
)
```

:::{note}
Creating a client that is limited to a specific tenant (Active Directory, or similar)
has not been tested and might require some customisation of the
provided `MicrosoftOIDCClient`.
:::

(adding-support-for-other-oidc-providers)=
## Adding support for other OIDC Providers

To support other OIDC providers, you can implement a custom client based on
the `OIDCClient` class configuring the required attributes.

:::{important}
HIdP only supports the Authorization Code flow. Other flows, like the Implicit flow,
are considered insecure and will not work.
:::

```{eval-rst}
.. autoclass:: hidp.federated.providers.base.OIDCClient
   :members:
```

:::{tip}
OpenID Connect configuration can usually be extracted from the provider's discovery
document, commonly found at: *https://**\<provider\>**/.well-known/openid-configuration*
:::

Make sure to register your custom client:
```python
from hidp import config as hidp_config

hidp_config.configure_oidc_clients(
    MyCustomOIDCClient(client_id="your-client-id"),
)
```

