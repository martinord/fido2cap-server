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

import DOMPurify from 'isomorphic-dompurify';
import base64url from 'base64url';
import { Router } from 'express';

import { User, UserModel } from '../models/user';
import { isEmailAddress, generateRandomUserId } from '../helpers/user';
import { login, logout } from '../helpers/session';

export const registration : Router = Router();
export const authentication : Router = Router();

/**
 * Registration
 */
registration.get('/', async (req, res) => {
    try {
        var username : string = req.query.username ? req.query.username as string : 'user';

        username = DOMPurify.sanitize(username, {USE_PROFILES: {html: false}});

        if(!isEmailAddress(username)) username = `${username}@${globalThis.rpID}`;

        const user : User = (await UserModel.findOne({username: username}) as unknown) as User;
        
        let userId = user ? user.id : await generateRandomUserId();

        req.session.userId = userId;
        req.session.username = username;

        const opts: GenerateRegistrationOptionsOpts = {
            rpName: 'SimpleWebAuthn Example',
            rpID: globalThis.rpID,
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

registration.post('/', async (req, res) => {
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
                expectedRPID: globalThis.rpID,
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
authentication.get('/', async (req, res) => {
    try {
        const opts: GenerateAuthenticationOptionsOpts = {
            timeout: 60000,
            allowCredentials: [],
            userVerification: 'required',
            rpID: globalThis.rpID,
        };

        const options = generateAuthenticationOptions(opts);

        req.session.challenge = options.challenge;
        
        res.send(options);

    } catch (error) {
        res.status(500).send("User is not registered in the database");
    }
});

authentication.post('/', async (req, res) => {
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
                expectedRPID: globalThis.rpID,
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

            req.session.sessionId = await login(loggedUserId, req.session.rhid, req.session.gatewayHash);
        }

        req.session.challenge = "";
        res.send({ verified });

    } catch (error) {
        res.status(500).send("User is not registered in the database");
    }
});

module.exports = { registration, authentication }