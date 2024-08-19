# Management Commands
HIdP exposes some useful management commands that can be run via shell or by other
means such as cron or Celery.

## refresh_oidc_clients_jwks
JWKs (JSON Web Keys) shouldn't change that often so they are cached for a long time.
The ``refresh_oidc_clients_jwks`` command refreshes the JWKs for
all OIDC clients.

Having to fetch the keys on demand slows down the OIDC process and adds another point of
failure.

We recommend to run this management command *daily* The command can also be run
manually in case of "emergency" or other special occasions (i.e. when the provider has
rotated their keys, or a new provider is added).

:::{note}
Without a proper cache setup, the JWKs cannot be cached correctly, see
[Cache](project:installation.md#cache) for more information.
:::

## cleartokens
The ``cleartokens`` management command removes expired refresh, access
and ID tokens. We recommend to run this command *daily* if HIdP is used as an OIDC
Provider.

:::{note}
For more information, please see [cleartokens](https://django-oauth-toolkit.readthedocs.io/en/latest/management_commands.html#cleartokens)
:::
