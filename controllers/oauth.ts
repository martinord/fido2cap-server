import passport from 'passport';
import { Router, NextFunction } from 'express';
import { User } from '../models/user';
import { sessionDatabase } from '../models/session';

export const oauth2 : Router = Router();

oauth2.get('/zitadel', passport.authenticate('openidconnect', { scope: ['openid', 'profile', 'email'] }));
oauth2.get('/zitadel/callback', async (req, res, next) => {
  passport.authenticate('openidconnect', { failureRedirect: '/login' }, async (err:Error, user:User, info:Error) => {
    
    // info exists and is not empty
    if (info && Object.keys(info).length > 0) {
      console.error("Info OAuth2: ", info);
      return res.redirect('/');
    } 
    
    if (err) {
      console.error("Error OAuth2:", err);
      return res.redirect('/');
    }

    req.logIn(user, async (err) => {
      
      if (err) {
      
        console.error('Login error:', err);
        return res.redirect('/');
      
      } 
      // Correct OAuth2 login
      req.session.sessionId = await sessionDatabase.loginSession(user.username, req.session.rhid, req.session.gatewayHash);
      return res.redirect('/user');
    
    });

  }) (req, res, next);
});

module.exports = { oauth2 };