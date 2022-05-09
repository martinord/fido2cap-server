# WebAuthn Authentication Server

This is a WebAuthn Authentication Server with a simple login and administration interface.

## Usage

For registering a new user, using resident credentials in a security key, access to https://localhost:4443/admin. Then, for authentication, access the root webpage at https://localhost:4443.

An administrator role can also be assigned directly at the database document of a user (`isAdmin: true`). After the application restart, only administrators will be able to access the admin dashboard.

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
SESSION_EXPIRE_TIME=<session duration in minutes>
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
option sessiontimeout '<session duration in minutes>'
```

### Configuration complete example

In this configuration, we assume there is a FAS server at the IP `192.168.58.100` whose assigned domain name is `fas.localhost.pri`, with the corresponding TLS certificates that have been installed in openNDS and are accepted by the client.

#### Application `.env` file

```bash
SESSION_KEY=880676ec6b89063a31480f7cd8160023b3692e1d261cd1e7d3d1c35dd8656e7f9b075dd1e82f7b3de10265714c8b3c3e50accd25dd5fa67c51574da308020411
SESSION_EXPIRE_TIME=15
CAPTIVE_PORTAL=true
FAS_SHARED_KEY=eaf50a8dafe491222e5e8e47099bca57
ORIGIN=fas.localhost.pri
HOST=192.168.58.100
```

#### openNDS configuration

```bash
config opennds
	# enable opennds
	option enabled 1
	option fwhook_enabled '1'
	
	# configure interface and clients
	option gatewayinterface 'br-clients' 
	option maxclients '250'
	option sessiontimeout '15'

	# FAS
	option checkinterval '10'
	option fasport '8000'
	option fasremotefqdn 'fas.localhost.pri'
	option fasremoteip '192.168.58.100'
	option faspath '/'
	option faskey 'eaf50a8dafe491222e5e8e47099bca57'
	option fas_secure_enabled '3'

	# Allow ports for DNS and DHCP
	list users_to_router 'allow tcp port 53'
	list users_to_router 'allow udp port 53'
	list users_to_router 'allow udp port 67'
```

### Optional openNDS configuration

- `option gatewayname 'My Gateway'`: allows setting different gateway names in different routers so that this FAS server can distinguish them.
- `option authidletimeout '120'`: configure the time (minutes) after a client is disconnected if idle.
- `option checkinterval '10'`: configure the time (seconds) openNDS will query the FAS server. The more frequent the queries are, the faster it will authorize the user.

### Known issues

- Notice that the development TLS certificates will not be valid. openNDS will not trust them by default. You need valid TLS certificates, like the ones issued by Let's Encrypt (Certbot).
- The registered users in WebAuthn are tight to the FQDN. 

## Based on
Based on the reference implementation of **@simplewebauthn/server** and **@simplewebauthn/browser**.

- Src: https://github.com/MasterKale/SimpleWebAuthn
- Guide: https://simplewebauthn.dev/docs/advanced/example-project
