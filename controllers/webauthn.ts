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

import { User, userDatabase } from '../models/user';
import { isEmailAddress } from '../helpers/user';
import { sessionDatabase } from '../models/session';

export const registration : Router = Router();
export const authentication : Router = Router();

/**
 * Registration
 */
registration.get('/', async (req, res) => {
    try {
        var username : string = req.query.username ? req.query.username as string : 'user';
        var nonDiscoverable : boolean = (req.query.nonDiscoverable == "true");

        username = DOMPurify.sanitize(username, {USE_PROFILES: {html: false}});

        if(!isEmailAddress(username)) username = `${username}@${globalThis.rpID}`;

        const user : User = await userDatabase.getByUsername(username);
        
        let userId = user ? user.id : await userDatabase.generateRandomUserId();

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
                requireResidentKey: !nonDiscoverable,
                userVerification: nonDiscoverable? 'discouraged' : 'required',
                residentKey: nonDiscoverable? 'discouraged' : 'required'
            },
            supportedAlgorithmIDs: [-7, -257],
        };

        const options = generateRegistrationOptions(opts);

        req.session.challenge = options.challenge;

        res.send(options);

    } catch (error) {
        res.status(500).send("Looks we did something wrong ...");
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

        if (verified && registrationInfo && userId && username) {
            const { credentialPublicKey, credentialID, counter } = registrationInfo;

            const newDevice: AuthenticatorDevice = {
                credentialPublicKey,
                credentialID,
                counter,
                transports: body.transports,
            };

            await userDatabase.addDeviceToUser(userId, username, newDevice);

            req.session.challenge = "";
            req.session.userId = "";
            req.session.username = "";

            res.send({ verified });
        }
    } catch (error) {
        res.status(500).send("Looks we did something wrong ...");
    }
});

/**
 * Login
 */
authentication.get('/', async (req, res) => {

    var username : string = req.query.username ? req.query.username as string : '';
    var nonDiscoverable : boolean = (req.query.nonDiscoverable == "true");

    username = DOMPurify.sanitize(username, {USE_PROFILES: {html: false}});

    if(!isEmailAddress(username)) username = `${username}@${globalThis.rpID}`;
    
    try {
        const opts: GenerateAuthenticationOptionsOpts = {
            timeout: 60000,
            allowCredentials: nonDiscoverable ? await userDatabase.getAllowCredentialsByUsername(username) : [],
            userVerification: nonDiscoverable ? 'discouraged' : 'required',
            rpID: globalThis.rpID,
        };

        const options = generateAuthenticationOptions(opts);

        req.session.challenge = options.challenge;
        var user = await userDatabase.getByUsername(username);
        if(nonDiscoverable && user) req.session.userId = user.id;
        
        res.send(options);

    } catch (error) {
        console.log(error);
        res.status(500).send(error);
    }
});

authentication.post('/', async (req, res) => {
    const body: AuthenticationCredentialJSON = req.body;

    try {
        // You need to know the user by this point

        // First factor authentication gives the loggedUserId in the userHandle (resident credential)
        const loggedUserId = body.response.userHandle || req.session.userId;
        const user : User = await userDatabase.getById(loggedUserId);
        
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
            sessionDatabase.logoutSession(req.session.sessionId);

            req.session.loggedUserId = loggedUserId;
            req.session.isAdmin = user.isAdmin;

            req.session.sessionId = await sessionDatabase.loginSession(loggedUserId, req.session.rhid, req.session.gatewayHash);
        }

        req.session.challenge = "";
        res.send({ verified });

    } catch (error) {
        res.status(500).send("Looks we did something wrong ...");
    }
});

module.exports = { registration, authentication }