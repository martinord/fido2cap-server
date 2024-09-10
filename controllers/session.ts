import { Request, Response, NextFunction } from 'express';
import { sessionDatabase } from '../models/session';
import { User, userDatabase, RegisteredUser, AdminUser } from '../models/user';

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
    await sessionDatabase.logoutSession(req.session.sessionId);

    req.session.loggedUserId = "";
    req.session.sessionId = undefined;
    req.logout(next);
    // req.session.regenerate((err) => {
    //     if (err)
    //         res.status(500).send("Internal server error");
    //     else
    //         res.redirect(301, '/');
    // });
    // res.redirect(301, '/');
}

/**
 * User details
 */
export async function userDetails(req: Request, res: Response, next: NextFunction) {
    const loggedUserId = req.session.loggedUserId; 
    const isAuthenticated = req.isAuthenticated();

    if( isAuthenticated && loggedUserId && ( loggedUserId !== "" ) ) {
        const user : User = await userDatabase.getById(loggedUserId);
        try {

            res.send( { username: user.username, isAdmin: user.isAdmin } );

        } catch (error) {
            res.status(500).send("Internal server error");
        }
    } else {
        // May be authenticated using OAuth2
        if (isAuthenticated && req.session.passport.user) {
            res.send({ username: req.session.passport.user.username, isAdmin: false });
        } else
            res.send("You are not logged in!");
    }
}

export async function makeAdmin(req: Request, res: Response, next: NextFunction) {
    const user : AdminUser = req.body;

    try {
        if (user.username) await userDatabase.updateAdminUser(user.username, user.isAdmin);
    } catch (error) {
        res.status(500).send("Something went wrong!")
    }

    res.status(200).send();
}

export async function registeredUsers(req: Request, res: Response, next: NextFunction) {

    const registered_users : RegisteredUser[] = await userDatabase.getRegisteredUsers();  
  
    res.send({ users: registered_users });

}

module.exports = { authorizeOnlyAdmin, logoutRoute, registeredUsers, userDetails, makeAdmin }