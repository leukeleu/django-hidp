from hidp.federated.providers.base import OIDCClient


class ExampleOIDCClient(OIDCClient):
    # A perfectly valid OIDC client, with all the required attributes
    # and a valid provider key. It just doesn't work because it's an example.
    provider_key = "example"
    authorization_endpoint = "https://example.com/auth"
    token_endpoint = "https://example.com/token"
    userinfo_endpoint = "https://example.com/userinfo"
    jwks_uri = "https://example.com/jwks"
