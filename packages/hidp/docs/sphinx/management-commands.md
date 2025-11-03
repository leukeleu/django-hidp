# Management Commands

HIdP exposes some useful management commands that can be run manually via shell or
periodically using cron jobs or other scheduling tools.

## remove_stale_unverified_accounts

The `remove_stale_unverified_accounts` management command removes accounts that have
not been verified within a specific number of days after creation (90 days by default).

It is recommended to run this command *daily* to remove accounts that are unlikely to
ever be verified. This helps to keep the database clean and avoid storing unnecessary
(and potentially sensitive) data.

### Flags

The following optional flags are available:
  
`--days`
: Maximum number of days an account can remain unverified before removal.
  90 days if not specified.

`--dry-run`
: Output the number of accounts that would be removed, without actually performing the removal.
  `False` if not specified.

### Usage

For example, to get the number of accounts that have not been verified within the last 60 days,
without removing them, you can run the following command:

```bash
python manage.py remove_stale_unverified_accounts --days 60 --dry-run
```

In order to then remove these accounts, you can run the same command without the `--dry-run` flag:

```bash
python manage.py remove_stale_unverified_accounts --days 60
```

### Customizing the default value of the `--days` flag

To change the default value of the `--days` flag in your project, you can override the command
by subclassing `hidp.accounts.management.commands.remove_stale_unverified_accounts.Command`
and setting the `DEFAULT_MAX_DAYS` class attribute to the desired number of days.

For example, to change the default value of the `--days` flag to 30 days, you can create a new
management command in your project (e.g. `remove_stale_unverified_accounts.py`
in the `management/commands` directory of an app) with the following content:

```python
from hidp.accounts.management.commands.remove_stale_unverified_accounts import Command as BaseCommand

class Command(BaseCommand):
    DEFAULT_MAX_DAYS = 30
```

## remove_complete_and_stale_email_change_requests

The `remove_complete_and_stale_email_change_requests` management command removes
both completed and stale email change requests.

Requests are considered stale if they have not been completed within a specific
number of days (7 days by default).

It is recommended to run this command *daily* to remove completed requests and requests
that are unlikely to ever be completed. This helps to keep the database clean and avoid
storing unnecessary (and potentially sensitive) data.

### Flags

The following optional flags are available:

`--days`
: Maximum number of days an email change request can remain incomplete before removal.
  7 days if not specified.

`--dry-run`
: Output the number of requests that would be removed, without actually performing the removal.
  `False` if not specified.

### Usage

For example, to get the number of completed email change requests (created at any time)
and stale requests (created over 30 days ago and not completed), without removing them,
you can run the following command:

```bash
python manage.py remove_complete_and_stale_email_change_requests --days 30 --dry-run
```

In order to then remove these requests, you can run the same command without the `--dry-run` flag:

```bash
python manage.py remove_complete_and_stale_email_change_requests --days 30
```

### Customizing the default value of the `--days` flag

To change the default value of the `--days` flag in your project, you can override the command
by subclassing `hidp.accounts.management.commands.remove_complete_and_stale_email_change_requests.Command`
and setting the `DEFAULT_MAX_DAYS` class attribute to the desired number of days.

For example, to change the default value of the `--days` flag to 30 days, you can create a new
management command in your project (e.g. `remove_complete_and_stale_email_change_requests.py`
in the `management/commands` directory of an app) with the following content:

```python
from hidp.accounts.management.commands.remove_complete_and_stale_email_change_requests import Command as BaseCommand

class Command(BaseCommand):
    DEFAULT_MAX_DAYS = 30
```

## refresh_oidc_clients_jwks

When using OpenID Connect (OIDC) for federated login, the OIDC Provider's signing keys
(JSON Web Keys or JWKs) are used to verify the signatures of JSON Web Tokens (JWTs). 
These JWKs are fetched from the provider's JWKS (JSON Web Key Set) endpoint and are cached 
as they are not expected to change frequently.

The `refresh_oidc_clients_jwks` command refreshes the JWKs for all
[configure OIDC clients](project:configure-oidc-clients.md), ensuring the keys remain up to date.

Fetching the keys on demand can slow down the OIDC process and introduce an additional
point of failure. To avoid this, it is recommended to run this management command *daily*. 

The command can also be run manually in specific circumstances, such as when a provider has
rotated their keys, or a new provider is added.

:::{note}
Proper caching is required to store JWKs effectively. Without a correct cache setup,
the JWKs cannot be cached as intended,  For more details, see [Cache](project:installation.md#cache).
:::

### Usage

To refresh the JWKs for all configured OIDC clients, run the following command:

```bash
python manage.py refresh_oidc_clients_jwks
```

## cleartokens

When HIdP is configured as an [OIDC provider](project:configure-oidc-clients.md), token cleanup
is required to remove expired tokens regularly.

The `cleartokens` management command, provided by Django OAuth Toolkit, removes expired refresh,
access and ID tokens. 

It is recommended to run this command *daily* to ensure timely removal of expired tokens and
prevent indefinite token storage.

:::{note}
For more details about the `cleartokens` management command, see the
[Django OAuth Toolkit documentation](https://django-oauth-toolkit.readthedocs.io/en/latest/management_commands.html#cleartokens).
:::

### Usage

To remove expired tokens, run the following command:

```bash
python manage.py cleartokens
```
