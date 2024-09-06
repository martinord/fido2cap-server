import passport from 'passport';
import { Router, NextFunction } from 'express';
import { User } from '../models/user';
import { sessionDatabase } from '../models/session';

export const oauth2 : Router = Router();

oauth2.get('/zitadel', passport.authenticate('oauth2', { scope: ['openid', 'profile', 'email'] }));
oauth2.get('/zitadel/callback', async (req, res, next) => {
  passport.authenticate('oauth2', async (err:Error, user:User, info:Error) => {
    
    if (err) next(err);

    req.logIn(user, async (err) => {
      
      if (err) {
      
        console.error('Login error:', err);
        return res.redirect('/');
      
      } 
      // Correct OAuth2 login
      // TODO: Change to use the user ID from the OAuth2 profile
      req.session.sessionId = await sessionDatabase.loginSession("OAuth2 User", req.session.rhid, req.session.gatewayHash);
      return res.redirect('/user');
    
    });

  }) (req, res, next);
});

module.exports = { oauth2 };