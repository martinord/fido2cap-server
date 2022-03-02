/* eslint-disable @typescript-eslint/no-var-requires */
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import https from 'https';
import http from 'http';
import fs from 'fs';

import express from 'express';
import dotenv from 'dotenv';
import base64url from 'base64url';

import mongoose from 'mongoose';
import session from 'express-session';

dotenv.config();

import {
  // Registration
  generateRegistrationOptions,
  verifyRegistrationResponse,
  // Authentication
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
} from '@simplewebauthn/server';

import type {
  RegistrationCredentialJSON,
  AuthenticationCredentialJSON,
  AuthenticatorDevice,
} from '@simplewebauthn/typescript-types';

import { User, UserModel } from './models/user';

const app = express();

const { ENABLE_CONFORMANCE, ENABLE_HTTPS, SESSION_KEY } = process.env;

app.use(express.static('./public/'));

/**
 * Session
 */
 declare module "express-session" {
  interface SessionData {
    userId: string,
    username: string,
    challenge: string
  }
}
app.use(session({
  secret: SESSION_KEY as string,
  saveUninitialized: true,
  resave: true,
  cookie: { secure: true }
}))


app.use(express.json());

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(({ fidoRouteSuffix, fidoConformanceRouter }) => {
    app.use(fidoRouteSuffix, fidoConformanceRouter);
  });
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = 'localhost';
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export let expectedOrigin = '';

/**
 * Database Connection (MongoDB)
 */
mongoose.connect('mongodb://localhost:27017/mydb', {
  serverSelectionTimeoutMS: 5000,
  autoIndex: false,
  maxPoolSize: 10,
  socketTimeoutMS: 45000,
  family: 4
}).then((db) => console.log("db is connected")).catch((err) => console.log(err));

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */

/**
 * Helper functions
 */
async function generateRandomUserId(): Promise<string> {
  let outString: string = '';
  const inOptions: string = 'abcdefghijklmnopqrstuvwxyz0123456789';

  for (let i = 0; i < 32; i++) 
    outString += inOptions.charAt(Math.floor(Math.random() * inOptions.length));

  return (await UserModel.findOne({ id: outString })) ? generateRandomUserId() : outString;
}

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  try {
    const username = `${req.query.username ? req.query.username : "user"}@${rpID}`;

    const user : User = (await UserModel.findOne({username: username}) as unknown) as User;
    
    let userId = user ? user.id : await generateRandomUserId();

    req.session.userId = userId;
    req.session.username = username;

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: 'SimpleWebAuthn Example',
      rpID,
      userID: userId,
      userName: username,
      timeout: 60000,
      attestationType: 'direct',
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       * NOTE: If the user is registered, exclude the already registered devices from registration
       */
      excludeCredentials: user ? user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })) : [],
      /**
       * The optional authenticatorSelection property allows for specifying more constraints around
       * the types of authenticators that users to can use for registration
       * NOTE: 1st factor authentication (resident keys)
       */
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required'
      },
      /**
       * Support the two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
    };
  
    const options = generateRegistrationOptions(opts);
  
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    req.session.challenge = options.challenge;

    res.send(options);
  
  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }  
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationCredentialJSON = req.body;

  try {

    const userId = req.session.userId;
    const username = req.session.username;
    const expectedChallenge = req.session.challenge;

    let verification: VerifiedRegistrationResponse;
    try {
      const opts: VerifyRegistrationResponseOpts = {
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
      };
      verification = await verifyRegistrationResponse(opts);
    } catch (error) {
      const _error = error as Error;
      console.error(_error);
      return res.status(400).send({ error: _error.message });
    }

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;

      var user : User = (await UserModel.findOne({username: username}) as unknown) as User;

      const newDevice: AuthenticatorDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: body.transports,
      };

      if (user) {
        const existingDevice = user.devices.find(device => device.credentialID === credentialID);

        if (!existingDevice) {
          /**
           * Add the returned device to the user's list of devices
           */
          user.devices.push(newDevice);

          await UserModel.updateOne({ id: userId }, { $set: { devices: user.devices } });
        }
      
      } else {
        // Create new user if it does not already exist
        UserModel.createCollection().then( async function() {
          const user_db = new UserModel({ id: userId, username: username, devices: [ newDevice ] });
          user_db.save();
        })
      }

      req.session.challenge = "";
      req.session.userId = "";
      req.session.username = "";
      res.send({ verified });
    }
  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {

  try {
    // const user : User = (await UserModel.findOne({id: userId}) as unknown) as User;

    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: [],
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification: 'required',
      rpID,
    };
  
    const options = generateAuthenticationOptions(opts);
  
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    req.session.challenge = options.challenge;
    
    req.session.userId = "";
    res.send(options);

  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationCredentialJSON = req.body;

  try {
    // You need to know the user by this point

    // First factor authentication gives the userId in the userHandle (resident credential)
    const userId = body.response.userHandle;
    const user : User = (await UserModel.findOne({id: userId}) as unknown) as User;
    
    const expectedChallenge = req.session.challenge;

    let dbAuthenticator;
    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    // "Query the DB" here for an authenticator matching `credentialID`
    for (const dev of user.devices) {
      if (dev.credentialID.equals(bodyCredIDBuffer)) {
        dbAuthenticator = dev;
        break;
      }
    }

    if (!dbAuthenticator) {
      throw new Error(`could not find authenticator matching ${body.id}`);
    }

    let verification: VerifiedAuthenticationResponse;
    try {
      const opts: VerifyAuthenticationResponseOpts = {
        credential: body,
        expectedChallenge: `${expectedChallenge}`,
        expectedOrigin,
        expectedRPID: rpID,
        authenticator: dbAuthenticator,
      };
      verification = verifyAuthenticationResponse(opts);
    } catch (error) {
      const _error = error as Error;
      console.error(_error);
      return res.status(400).send({ error: _error.message });
    }

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update the authenticator's counter in the DB to the newest count in the authentication
      dbAuthenticator.counter = authenticationInfo.newCounter;
      req.session.userId = userId;
    }

    req.session.challenge = "";
    res.send({ verified });

  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
});

/**
 * User details
 */
 app.get('/user-details', async (req, res) => {
  
  const userId = req.session.userId; 

  if( userId && ( userId !== "" ) ) {
    const user : User = (await UserModel.findOne({ id: userId }) as unknown) as User;
    try {

      res.send( { username: user.username} );
    
    } catch (error) {
      res.status(500).send("Internal server error");
    }
  } else {
    res.send("You are not logged in!");
  }
 
});

/**
 * User logout
 */
 app.get('/logout', async (req, res) => {
  
  req.session.userId = ""; 
  res.redirect(301, '/');
 
});

if (ENABLE_HTTPS) {
  const host = '127.0.0.1';
  const port = 4443;
  expectedOrigin = `https://${rpID}:${port}`;

  https
    .createServer(
      {
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = '127.0.0.1';
  const port = 8000;
  expectedOrigin = `http://localhost:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
