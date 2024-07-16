from hidp.federated.providers.base import OIDCClient


class OIDCCertificationProvider(OIDCClient):
    provider_key = "oidc_certification"
    name = "OIDC Certification"
    issuer = "https://www.certification.openid.net/test/a/HIdP/"
    authorization_endpoint = (
        "https://www.certification.openid.net/test/a/HIdP/authorize"
    )
    token_endpoint = "https://www.certification.openid.net/test/a/HIdP/token"  # noqa: S105 (not a secret)
    userinfo_endpoint = "https://www.certification.openid.net/test/a/HIdP/userinfo"
    jwks_uri = "https://www.certification.openid.net/test/a/HIdP/jwks"
