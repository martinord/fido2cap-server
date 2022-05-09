import https from 'https';
import http from 'http';
import fs from 'fs';

import express, { Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';

import mongoose from 'mongoose';
import session from 'express-session';

dotenv.config();

import * as fas from './controllers/fas';
import * as webauthn from './controllers/webauthn';
import { authorizeOnlyAdmin, logoutRoute, registeredUsers, userDetails } from './controllers/session';
import { isAdministratorConfigured } from './helpers/user';

declare global {
  /**
   * Administration start up: allow using administrator privileges when admin not yet registered
   */
  var administratorConfigured: boolean;
  
  /**
   * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
   * represents the expected URL from which registration or authentication occurs.
   */
  var rpID : string;
  var expectedOrigin : string;
}

const app = express();

const { ENABLE_HTTPS, SESSION_KEY, SESSION_EXPIRE_TIME, CAPTIVE_PORTAL, ORIGIN, HOST } = process.env;

globalThis.rpID = ORIGIN || 'localhost';

/**
 * Session
 */
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
  app.post('/', fas.authmonController);
  app.use(fas.clientController);
  app.use(fas.redirection);
}

app.use(express.static('./public/'));
app.use(express.json());

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

app.use('/api/registration', authorizeOnlyAdmin, webauthn.registration);
app.use('/api/authentication', webauthn.authentication);

app.use('/api/user-details', userDetails);
app.use('/api/registered-users', authorizeOnlyAdmin, registeredUsers);
app.use('/logout', logoutRoute);

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
  // RP origin should always be HTTPS for WebAuthn to work
  globalThis.expectedOrigin = `https://${rpID}:${port}`;

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
  // This configuration should be used behind a HTTPS reverse proxy
  const host = HOST || '127.0.0.1';
  const port = 4443;
  // RP origin should always be HTTPS for WebAuthn to work
  globalThis.expectedOrigin = `https://${rpID}:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
