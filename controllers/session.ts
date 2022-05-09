import { Request, Response, NextFunction } from 'express';
import { logout } from '../helpers/session';
import { User, UserModel, RegisteredUser } from '../models/user';
import { SessionModel } from '../models/session';

declare module "express-session" {
    interface SessionData {
      sessionId: string,
      loggedUserId: string,
      userId: string,
      username: string,
      challenge: string,
      isAdmin: Boolean,
      rhid: string,
      gatewayHash: string,
      originUrl: string
    }
  }

/**
 * Session authorization Middleware
 */
export function authorizeOnlyAdmin(req: Request, res: Response, next: NextFunction) {

    if (globalThis.administratorConfigured && !req.session.loggedUserId) return res.sendStatus(401);

    if (globalThis.administratorConfigured && !req.session.isAdmin) return res.sendStatus(403);

    next();
}

/**
 * User logout
 */
export async function logoutRoute(req: Request, res: Response, next: NextFunction) {
    await logout(req.session.sessionId);

    req.session.loggedUserId = "";
    req.session.sessionId = undefined;
    res.redirect(301, '/');
}

/**
 * User details
 */
export async function userDetails(req: Request, res: Response, next: NextFunction) {
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
}

export async function registeredUsers(req: Request, res: Response, next: NextFunction) {

    const users : User[] = (await UserModel.find() as unknown) as User[];
  
    var registered_users : RegisteredUser[] = await Promise.all(users.map( async (user) => (
      {
        username: user.username,
        nofdevices: user.devices.length,
        activesessions: (await SessionModel.find({ userId: user.id })).length
      }
    )));
  
    res.send({ users: registered_users });

}

module.exports = { authorizeOnlyAdmin, logoutRoute, registeredUsers, userDetails }