# WebAuthn Authentication Server

This is a WebAuthn Authentication Server with a simple login and administration interface.

## Usage

For registering a new user, using resident credentials in a security key, access to https://localhost:4443/admin. Then, for authentication, access the root webpage at https://localhost:4443.

Notice that TLS must be enabled, as it is a requirement of the WebAuthn standard.

## Development Quick Start

```bash
npm install         # installs NPM dependencies
npm build:styles    # builds the CSS styles
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

## Based on
Based on the reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**.

- Src: https://github.com/MasterKale/SimpleWebAuthn
- Guide: https://simplewebauthn.dev/docs/advanced/example-project
