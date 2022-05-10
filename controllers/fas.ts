import { Request, Response } from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import { Session, sessionDatabase } from '../models/session';

dotenv.config();

const { CAPTIVE_PORTAL, FAS_SHARED_KEY } = process.env;

/**
 * Middleware that decodes, decrypts and parses the request 
 * to log FAS parameters in the session
 */
export function clientController (req : Request, res : Response, next : Function) {
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

        // Get hid, gatewayname and redirection url
        let hid : string = fas.split("hid=")[1].split(",")[0];
        let gatewayName : string = fas.split("gatewayname=")[1].split(",")[0];
        let originUrl : string = decodeURIComponent(fas.split("originurl=")[1].split(",")[0]);

        // Calculate gatewayHash
        let gatewayHash : string = crypto.createHash('sha256').update(gatewayName, 'utf8').digest().toString('hex');

        // Calculate and store rhid
        let rhid : string = crypto.createHash('sha256').update(hid+FAS_SHARED_KEY, 'utf8').digest().toString('hex');
        console.log("[CLIENT Request] Request sent with HID: " + hid);
        console.log("[ - CLIENT Request] Calculated RHID: " + rhid);

        // Store details in session
        req.session.rhid = rhid;
        req.session.gatewayHash = gatewayHash;
        req.session.originUrl = originUrl;
    }

    next();
};

/**
 * Captive Portal URL redirection after authentication
 */

export function redirection(req : Request, res : Response, next : Function) {
    // if the client has a valid authenticated session
    if (req.session.loggedUserId && ( req.session.loggedUserId !== "" ) && req.session.originUrl) {
      var url = req.session.originUrl;
      delete req.session.originUrl // only redirect once
      res.redirect(307, url);
    }
    else
        next(); 
}

/**
 * Requests from Authmon (OpenNDS) to authenticate clients
 * Request types:
 *  - View
 *  - Clear
 */
export async function authmonController (req: Request, res: Response) {
    let request = req.body;
  
    if(!request.auth_get || !request.gatewayhash || !request.payload) return;
  
    console.log("[Authmon Request] " + request.auth_get + " from " + request.gatewayhash);
  
    switch (request.auth_get) {
      case "clear":
        console.log("[ - Authmon Request CLEAR] The authlist is cleared!");
        await sessionDatabase.clearGatewaySessions(request.gatewayhash );
        break;
      
      case "list":
        console.log("[ - Authmon Request LIST] The authlist should be sent and cleared! (UNDER IMPLEMENTATION)");
        // TODO: send not authenticated sessions and clear
        break;
  
      case "view":
        let request_payload = Buffer.from(request.payload, 'base64').toString('utf-8');
  
        let sessions : Session[] = await sessionDatabase.getUnauthenticatedGatewaySessions(request.gatewayhash);
  
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
                await sessionDatabase.markAuthenticatedGatewaySession(request.gatewayhash, rhid);
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

module.exports = { authmonController, clientController, redirection };