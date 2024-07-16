# Headless Identity Provider

Leukeleu's Headless Identity Provider (HIdP).

## Development

See [docker/README.md](docker/README.md)

## Releasing

Each PR merged to `main` will automatically run the `release-drafter` workflow. This will create/update
draft releases for both the next release candidate and the next final release. The draft release will
contain all the PRs merged since the previous release of the same type.

Publishing a release is done by editing the draft release, double checking the PRs and then clicking the
"Publish release" button. This will create a new release and tag the commit with the version number.
This tag will trigger the `release` workflow which will build and push the Python package to DevPI.
