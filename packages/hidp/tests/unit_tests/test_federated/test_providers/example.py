import base64
import hashlib

from hidp.federated.providers.base import OIDCClient


class ExampleOIDCClient(OIDCClient):
    # A perfectly valid OIDC client, with all the required attributes
    # and a valid provider key. It just doesn't work because it's an example.
    provider_key = "example"
    issuer = "https://example.com"
    authorization_endpoint = "https://example.com/auth"
    token_endpoint = "https://example.com/token"
    userinfo_endpoint = "https://example.com/userinfo"
    jwks_uri = "https://example.com/jwks"


def code_challenge_from_code_verifier(cove_verifier):
    # Re-implements code_challenge generation for testing purposes.
    return (
        base64.urlsafe_b64encode(hashlib.sha256(cove_verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
