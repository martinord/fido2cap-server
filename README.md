# WebAuthn Authentication Server

This is a WebAuthn Authentication Server with a simple login and administration interface.

## Usage

For registering a new user, using resident credentials in a security key, access to https://localhost:4443/admin. Then, for authentication, access the root webpage at https://localhost:4443.

Notice that TLS must be enabled, as it is a requirement of the WebAuthn standard.

## Development Quick Start

```bash
npm install         # installs NPM dependencies
npm build:styles    # builds the CSS styles
npm build:webauthn  # downloads the WebAuthn library
npm run db          # run the database (docker-compose required)
npm start           # starts the server
```

### TLS Certificates

```bash
echo "ENABLE_HTTPS=true" >> .env
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.key -out localhost.crt
```

### Session secret key generation

```bash
echo "\nSESSION_KEY=`openssl rand -hex 64`" >> .env
```

## OpenNDS integration

This server can be used as a [Forwarding Authentication Service (FAS) server](https://opennds.readthedocs.io/en/stable/fas.html) for authentication in [openNDS](https://github.com/openNDS/openNDS) captive portal software.

### Configuration

For enabling it, you should specify some enironment variables first in the `.env` file:

```bash
CAPTIVE_PORTAL=true
FAS_SHARED_KEY=<the shared secret of 32 bytes>
ORIGIN=<your FQDN>
HOST=<your server ip address>
```

The `FAS_SHARED_KEY` should be a shared random value of 32 bytes, configured in openNDS. It can be generated with:

```bash
echo $RANDOM | sha1sum | head -c 32; echo;
```

In the openNDS configuration file, you can use:

```bash
option fas_secure_enabled '3'
option fasport '4443'
option faspath '/'
option fasremoteip '<your server ip address>'
option fasremotefqdn '<your FQDN>'
option faskey '<the shared secret of 32 bytes>'
```

### Known issues

- Notice that the development TLS certificates will not be valid. openNDS will not trust them by default. You need valid TLS certificates, like the ones issued by Let's Encrypt (Certbot).
- The registered users in WebAuthn are tight to the FQDN. 

## Based on
Based on the reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**.

- Src: https://github.com/MasterKale/SimpleWebAuthn
- Guide: https://simplewebauthn.dev/docs/advanced/example-project
