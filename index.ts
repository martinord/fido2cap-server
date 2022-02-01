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

const { ENABLE_CONFORMANCE, ENABLE_HTTPS } = process.env;

app.use(express.static('./public/'));
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
mongoose.connect('mongodb://localhost:27017/mydb').then( function() {
  console.log('Successfully connected to users database');
});

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';

UserModel.createCollection().then( async function() {
  await UserModel.deleteMany({ id: loggedInUserId }); // delete from previous runs
  const loggedInUser = new UserModel({ id: loggedInUserId, username: `user@${rpID}`});
  loggedInUser.save();
})

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  try {

    const user : User = (await UserModel.findOne({id: loggedInUserId}) as unknown) as User;

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: 'SimpleWebAuthn Example',
      rpID,
      userID: user.id,
      userName: user.username,
      timeout: 60000,
      attestationType: 'indirect',
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      excludeCredentials: user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })),
      /**
       * The optional authenticatorSelection property allows for specifying more constraints around
       * the types of authenticators that users to can use for registration
       */
      authenticatorSelection: {
        userVerification: 'preferred',
        requireResidentKey: false,
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
    await UserModel.updateOne({ id: loggedInUserId }, { $set: { currentChallenge: options.challenge } });

    res.send(options);
  
  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }  
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationCredentialJSON = req.body;

  try {

    const user : User = (await UserModel.findOne({id: loggedInUserId}) as unknown) as User;
    const expectedChallenge = user.currentChallenge;

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

      const existingDevice = user.devices.find(device => device.credentialID === credentialID);

      if (!existingDevice) {
        /**
         * Add the returned device to the user's list of devices
         */
        const newDevice: AuthenticatorDevice = {
          credentialPublicKey,
          credentialID,
          counter,
          transports: body.transports,
        };
        user.devices.push(newDevice);
      }

      await UserModel.updateOne({ id: loggedInUserId }, { $set: { devices: user.devices } });

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
    // You need to know the user by this point
    const user : User = (await UserModel.findOne({id: loggedInUserId}) as unknown) as User;

    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports ?? ['usb', 'ble', 'nfc', 'internal'],
      })),
      /**
       * This optional value controls whether or not the authenticator needs be able to uniquely
       * identify the user interacting with it (via built-in PIN pad, fingerprint scanner, etc...)
       */
      userVerification: 'preferred',
      rpID,
    };
  
    const options = generateAuthenticationOptions(opts);
  
    /**
     * The server needs to temporarily remember this value for verification, so don't lose it until
     * after you verify an authenticator response.
     */
    await UserModel.updateOne({ id: loggedInUserId }, { $set: { currentChallenge: options.challenge } });

    res.send(options);

  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationCredentialJSON = req.body;

  try {
    // You need to know the user by this point
    const user : User = (await UserModel.findOne({id: loggedInUserId}) as unknown) as User;
    const expectedChallenge = user.currentChallenge;

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
    }

    res.send({ verified });

  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
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
