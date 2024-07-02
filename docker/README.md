# Headless Identity Provider development using Docker Compose

> Note that this is for **development only**, the containers spawned for
this project are configured for development ease, not security.

Also see <https://docs.docker.com/compose/overview/>

The setup provides these containers:

* nginx
* python (custom image)
* postgres
* node (custom image)

## To run locally:

### 0. Make sure Docker Desktop and mkcert are installed

#### Docker Desktop

<https://docs.docker.com/docker-for-mac/install/> or `brew cask install docker`

#### mkcert

<https://github.com/FiloSottile/mkcert>

```sh
brew install mkcert
brew install nss  # if you use Firefox
mkcert -install
```

### 1. Create certificates to access the site via https

Create a local (wildcard) cert using `mkcert`

```sh
mkcert -cert-file ./docker/conf/certs/cert.pem -key-file \
       ./docker/conf/certs/key.pem \
       hidp.test "*.hidp.test" local.hidp.leukeleu.dev
```


### 2. Configure `/etc/hosts`

Add the following line to `/etc/hosts`:

```
127.0.0.1       hidp.test www.hidp.test local.hidp.leukeleu.dev
```

> *TIP*: [Gas Mask](https://github.com/2ndalpha/gasmask) is a nice tool
to manage host file entries. Install with `brew cask install gas-mask`


### 3. Configure project settings (optional)

On startup, the `python` container will copy `hidp_sandbox/local.example.ini` to 
`hidp_sandbox/local.ini` (if it does not yet exist).

To manually configure the settings, first copy the example file:

```sh
cp hidp_sandbox/local.example.ini hidp/local.ini
```

Then edit the settings to your liking.


### 4. Running the containers

Normally, you start all containers in the foreground:

```sh
docker-compose up
```

You can also start all containers in the background:

```sh
docker-compose up -d
```
