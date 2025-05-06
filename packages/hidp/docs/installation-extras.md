# Installation Extras

The `hidp` package has some optional dependencies to provide additional features.
These dependencies can be selected using the `[extra]` syntax when installing the package.

## Available Extras

`oidc_provider`
: Adds support for OpenID Connect (OIDC) provider functionalities.
  
`otp`
: Adds support for one-time passwords (OTP).
  
`recommended`
: Recommended dependencies to get a fully featured account system (includes OTP support).

`all`
: Install all possible extras.

### Usage

In most cases the recommended set of extras should be used.

To add OIDC provider support you can select the `oidc_provider` extra:

```
pip install django-hidp[recommended,oidc_provider]
```

It's also possible to only install the `oidc_provider` extra, and omit the recommended extras:

```
pip install django-hidp[oidc_provider]
```

## Base Installation

Installing `hidp` without any extras is also possible:

```
pip install django-hidp
```

This will result in a bare-bones installation, without support for one-time passwords (OTP).
