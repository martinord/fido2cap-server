import https from 'https';
import http from 'http';
import fs from 'fs';

import express, { Request, Response, NextFunction } from 'express';
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

import { RegisteredUser, User, UserModel } from './models/user';
import { Session, SessionModel } from './models/session';
import * as fas from './fas';

import DOMPurify from 'isomorphic-dompurify';

const app = express();

const { ENABLE_HTTPS, SESSION_KEY, SESSION_EXPIRE_TIME, CAPTIVE_PORTAL, ORIGIN, HOST } = process.env;

/**
 * Session
 */
declare module "express-session" {
  interface SessionData {
    sessionId: string,
    loggedUserId: string,
    userId: string,
    username: string,
    challenge: string,
    isAdmin: Boolean,
    rhid: string
  }
}
app.use(session({
  secret: SESSION_KEY as string,
  saveUninitialized: true,
  resave: true,
  cookie: { 
    secure: ENABLE_HTTPS ? true : false,
    // Expiration time in minutes, set to 1h by default
    maxAge: ((SESSION_EXPIRE_TIME ?? 60) as number) * 60 * 1000
  }
}))

/**
 * Acticvate Captive Portal integration
 * Compatible as FAS Authentication Server in OpenNDS
 * FAS: Forward Authentication Server
 */

if (CAPTIVE_PORTAL) {
  app.use(express.urlencoded({extended: true}));
  app.post('/', fasController);
  app.use(fas.middleware);
}

/**
 * Requests from Authmon (OpenNDS) to authenticate clients
 * Request types:
 *  - View
 *  - Clear
 */
async function fasController (req: Request, res: Response) {
  let request = req.body;

  if(!request.auth_get || !request.gatewayhash || !request.payload) return;

  console.log("[Authmon Request] " + request.auth_get + " from " + request.gatewayhash);

  switch (request.auth_get) {
    case "clear":
      console.log("[ - Authmon Request CLEAR] The authlist is cleared!");
      await SessionModel.deleteMany({});
      break;
    
    case "list":
      console.log("[ - Authmon Request LIST] The authlist should be sent and cleared! (UNDER IMPLEMENTATION)");
      // TODO: send not authenticated sessions and clear
      break;

    case "view":
      let request_payload = Buffer.from(request.payload, 'base64').toString('utf-8');

      let sessions : Session[] = (await SessionModel.find({ fasAuthentication: false }) as unknown) as Session[];

      switch (request_payload) {
        case "*":
        case "none":
          console.log("[ - Authmon Request VIEW] The list of authenticated clients is sent!");
          let response : string = "";
          
          if ( sessions.length > 0 ) {
          
            sessions.forEach(session => {
              response += ("* " + session.rhid + "\n"); 
            });
          
            res.send(response);
            console.log("[ -- Authmon Request VIEW] Authenticated client rhid list: " + response.replace(/(\r\n|\n|\r)/gm, ", "));
          
          } else {
          
            res.send("*")
            console.log("[ -- Authmon Request VIEW] No new authenticated clients ");
          
          }  
          break;
        
        default:
          console.log("[ - Authmon Request VIEW] OpenNDS notification of authenticated clients!");
          let rhid_payload = request_payload.split("* ")[1] as string;
          let rhid_list = rhid_payload.split(" ") as string[];

          try {
            
            rhid_list.forEach( async (rhid:string) => {
              await SessionModel.updateOne({ rhid: rhid }, { $set: { fasAuthentication: true } });
              console.log("[ -- Authmon Request VIEW] Confirmation of client authentication: " + rhid);
            });

            res.send("ack");
          
          } catch (error) {
            console.log(error);
          }
      }
      break;
  }
};

app.use(express.static('./public/'));

app.use(express.json());

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = ORIGIN || 'localhost';
export let expectedOrigin = '';

/**
 * Database Connection (MongoDB)
 */
mongoose.connect('mongodb://localhost:27017/mydb', {
  serverSelectionTimeoutMS: 5000,
  autoIndex: true,
  maxPoolSize: 10,
  socketTimeoutMS: 45000,
  family: 4
}).then((db) => console.log("db is connected")).catch((err) => console.log(err));

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

function isEmailAddress( text : string): boolean {
  const regexp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);

  return regexp.test(text);
}

/**
 * Administration start up: allow using administrator privileges when admin not yet registered
 */
declare global {
  var administratorConfigured: boolean;
}

async function isAdministratorConfigured() : Promise<boolean> {
  
  return (await UserModel.find({ isAdmin: true }).count() > 0);

}

/**
 * Session authorization Middleware
 */
function authorizeOnlyAdmin(req: Request, res: Response, next: NextFunction) {

  if (globalThis.administratorConfigured && !req.session.loggedUserId) return res.sendStatus(401);

  if (globalThis.administratorConfigured && !req.session.isAdmin) return res.sendStatus(403);

  next();
}

/**
 * Session helpers
 */
async function logout(sessionId: string | undefined) {
  if ( sessionId && (sessionId != "")) {
    await SessionModel.findByIdAndDelete( new mongoose.Types.ObjectId(sessionId) ); 
  }
}

async function login(loggedUserId: string | undefined, rhid: string | undefined) : Promise<string> {
  if (loggedUserId && (loggedUserId != "")) {
    await SessionModel.createCollection();
    const session_db = new SessionModel({ userId: loggedUserId, rhid: rhid });
    const document = await session_db.save();
    return document.id;
  }
  return "";
}

/**
 * Registration
 */
app.get('/api/generate-registration-options', authorizeOnlyAdmin, async (req, res) => {
  try {
    var username : string = req.query.username ? req.query.username as string : 'user';

    username = DOMPurify.sanitize(username, {USE_PROFILES: {html: false}});

    if(!isEmailAddress(username)) username = `${username}@${rpID}`;

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
      excludeCredentials: user ? user.devices.map(dev => ({
        id: dev.credentialID,
        type: 'public-key',
        transports: dev.transports,
      })) : [],
      authenticatorSelection: {
        userVerification: 'required',
        residentKey: 'required'
      },
      supportedAlgorithmIDs: [-7, -257],
    };
  
    const options = generateRegistrationOptions(opts);
  
    req.session.challenge = options.challenge;

    res.send(options);
  
  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }  
});

app.post('/api/verify-registration', authorizeOnlyAdmin, async (req, res) => {
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
 * Login
 */
app.get('/api/generate-authentication-options', async (req, res) => {

  try {
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      allowCredentials: [],
      userVerification: 'required',
      rpID,
    };
  
    const options = generateAuthenticationOptions(opts);
  
    req.session.challenge = options.challenge;
    
    res.send(options);

  } catch (error) {
    res.status(500).send("User is not registered in the database");
  }
});

app.post('/api/verify-authentication', async (req, res) => {
  const body: AuthenticationCredentialJSON = req.body;

  try {
    // You need to know the user by this point

    // First factor authentication gives the loggedUserId in the userHandle (resident credential)
    const loggedUserId = body.response.userHandle;
    const user : User = (await UserModel.findOne({id: loggedUserId}) as unknown) as User;
    
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
      
      // Log out previous user
      logout(req.session.sessionId);

      req.session.loggedUserId = loggedUserId;
      req.session.isAdmin = user.isAdmin;

      req.session.sessionId = await login(loggedUserId, req.session.rhid);
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
 app.get('/api/user-details', async (req, res) => {
  
  const loggedUserId = req.session.loggedUserId; 

  if( loggedUserId && ( loggedUserId !== "" ) ) {
    const user : User = (await UserModel.findOne({ id: loggedUserId }) as unknown) as User;
    try {

      res.send( { username: user.username, isAdmin: user.isAdmin } );
    
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
  
  await logout(req.session.sessionId);

  req.session.loggedUserId = "";
  req.session.sessionId = undefined;
  res.redirect(301, '/');
 
});

/**
 * Registered Users
 */
 app.get('/api/registered-users', authorizeOnlyAdmin, async (req, res) => {

  const users : User[] = (await UserModel.find() as unknown) as User[];

  var registered_users : RegisteredUser[] = await Promise.all(users.map( async (user) => (
    {
      username: user.username,
      nofdevices: user.devices.length,
      activesessions: (await SessionModel.find({ userId: user.id })).length
    }
  )));

  res.send({ users: registered_users });
 
});

isAdministratorConfigured().then((admin) => {
  globalThis.administratorConfigured = admin;
  
  if(!admin) 
    console.log("Admin is not registered! Please, register a user at /admin and assign admin role at the database")
  else 
    console.log("admin is registered");  
});

if (ENABLE_HTTPS) {
  const host = HOST || '127.0.0.1';
  const port = 4443;
  expectedOrigin = `https://${rpID}:${port}`;

  https
    .createServer(
      {
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  // RP origin should always be HTTPS for WebAuthn to work
  // This configuration should be used behind a HTTPS reverse proxy
  const host = HOST || '127.0.0.1';
  const port = 8000;
  expectedOrigin = `https://${rpID}:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
