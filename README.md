# Hello, ID Please (HIdP)

Leukeleu's headless identity provider.

## Documentation

Read the [online documentation](https://leukeleu.github.io/django-hidp/) for usage and installation instructions.

## Development

See [docker/README.md](docker/README.md)

## Releasing

Each PR merged to `main` will automatically run the `release-drafter` workflow. This will create/update
draft releases for the next final release. The draft release will contain all the PRs merged since the
previous release.

Publishing a release is done by editing the draft release, double checking the PRs and then clicking the
"Publish release" button. This will create a new release and tag the commit with the version number.
This tag will trigger the `release` workflow which will build and push the Python package to PyPI.
