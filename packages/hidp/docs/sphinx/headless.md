# Headless mode

Headless mode allows clients to interact with HIdP programmatically, without a graphical user interface. This is particularly useful for automation, integration, and remote workflows.

## Session-based API

HIdP provides a session-based API for authentication and interaction.

### Session Management

Authentication is handled using [Django sessions](https://docs.djangoproject.com/en/stable/topics/http/sessions/). When a client logs in, a session cookie is set by the server. This cookie must be included in all subsequent requests to maintain authentication.

### CSRF Protection

All POST, PATCH, PUT, and DELETE requests to authenticated endpoints require a valid [CSRF token](https://docs.djangoproject.com/en/stable/ref/csrf/).
Clients should retrieve the CSRF token (typically available as a cookie named `csrftoken`) and include it in the `X-CSRFToken` header of each request.

### Key Features

- **Login:** Clients POST their credentials to the login endpoint. On success, authentication state is added to the session data.
- **Session Management:** The session persists across requests until explicitly logged out or expired.
- **Authenticated Endpoints:** Once authenticated, clients can access protected endpoints using the session cookie and must include the CSRF token for unsafe methods.
- **CSRF Token Requirement:** All POST, PATCH, PUT, and DELETE requests must include a valid CSRF token.
- **Logout:** Clients can terminate their session by calling the logout endpoint.

This approach is compatible with browsers, command-line tools, and scripts that support cookie and header management. It is ideal for scenarios where stateless tokens (such as JWTs) are not required.

## OpenAPI Specification

The documentation for the API endpoints is available in the [OpenAPI Specification](./redoc-static.html){.external}.

## Configuring Frontend URLs for Email Templates

When using HIdP in a frontend app, you must explicitly define the URLs used in email templates. There are **no defaults**: all URLs must be set in your Django settings.

Required settings:

```
EMAIL_VERIFICATION_URL
EMAIL_CHANGE_CONFIRMATION_URL
PASSWORD_CHANGED_URL
PASSWORD_RESET_URL
SET_PASSWORD_URL
EMAIL_CHANGE_CANCEL_URL
```

Each setting should be a string containing the required placeholders (e.g. `{token}`, `{uidb64}`) for your frontend routes. Example:

```python
EMAIL_VERIFICATION_URL = "https://your-frontend-app.example.com/verify/{token}/"
PASSWORD_RESET_URL = "https://your-frontend-app.example.com/reset/{uidb64}/{token}/"
```

Each setting must be defined and include the correct placeholder(s) for tokens or IDs (e.g. `{token}`, `{uidb64}`) as required by the email flow. If a required setting is missing or a placeholder is incorrect, HIdP will raise a configuration error during startup.
