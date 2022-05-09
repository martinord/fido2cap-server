import { Request, Response } from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';

dotenv.config();

const { CAPTIVE_PORTAL, FAS_SHARED_KEY } = process.env;

/**
 * Middleware that decodes, decrypts and parses the request 
 * to log FAS parameters in the session
 */
export function middleware (req : Request, res : Response, next : Function) {
    if(CAPTIVE_PORTAL && req.query.fas && req.query.iv) {
        // Decode fas from base64 and get iv query parameter
        let fas : string = req.query.fas as string;
        let iv : string = req.query.iv as string;
        fas = Buffer.from(fas, 'base64').toString('utf-8');
        
        // Decrypt the fas query parameter
        let decipher = crypto.createDecipheriv('aes-256-cbc', FAS_SHARED_KEY as string, iv);
        fas = Buffer.concat([
                decipher.update(Buffer.from(fas, 'base64')),
                decipher.final()
            ]).toString('utf-8');

        // Get hid and gatewayname
        let hid : string = fas.split("=")[1].split(",")[0];
        let gatewayName : string = fas.split("gatewayname=")[1].split(",")[0];

        // Calculate gatewayHash
        let gatewayHash : string = crypto.createHash('sha256').update(gatewayName, 'utf8').digest().toString('hex');

        // Calculate and store rhid
        let rhid : string = crypto.createHash('sha256').update(hid+FAS_SHARED_KEY, 'utf8').digest().toString('hex');
        console.log("[CLIENT Request] Request sent with HID: " + hid);
        console.log("[ - CLIENT Request] Calculated RHID: " + rhid);

        // Store details in session
        req.session.rhid = rhid;
        req.session.gatewayHash = gatewayHash;
    }

    next();
};

module.exports = { middleware };