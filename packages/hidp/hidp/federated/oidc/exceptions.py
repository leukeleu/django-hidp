class OAuth2Error(Exception):
    def __init__(self, error, description=None, uri=None):
        self.error = error
        self.description = description
        self.uri = uri

    def __str__(self):
        message = self.error
        if self.description:
            message += f": {self.description}"
        if self.uri:
            message += f" ({self.uri})"
        return message


class OIDCError(OAuth2Error):
    pass


class InvalidOIDCStateError(OIDCError):
    pass
