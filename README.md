# WebAuthn Authentication Server

## Development Quick Start

```bash
npm install
npm start
```

### TLS Certificates

```bash
echo "ENABLE_HTTPS=true" >> .env
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout localhost.key -out localhost.crt
```

## Based on
Based on the reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**.

- Src: https://github.com/MasterKale/SimpleWebAuthn
- Guide: https://simplewebauthn.dev/docs/advanced/example-project
