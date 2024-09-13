import passport from 'passport';
import { Router, NextFunction } from 'express';
import { User } from '../models/user';
import { sessionDatabase } from '../models/session';

export const oauth2 : Router = Router();

oauth2.get('/zitadel', (req, res, next) => {
  console.log("[OIDC] Redirecting to Zitadel with RHID:", req.session.rhid);
  passport.authenticate('openidconnect', { 
    scope: ['openid', 'profile', 'email'], 
    state: req.session.rhid,
  }) (req, res, next);
});

oauth2.get('/zitadel/callback', async (req, res, next) => {
  passport.authenticate('openidconnect', { failureRedirect: '/login' }, async (err:Error, user:User, info:any) => {

    // Recover state from query (RHID)
    // Captive Portal request identifier (RHID)
    console.log("[OIDC] Recovered RHID:", req.query.state);
    if (info.state || req.query.state)
      req.session.rhid = (req.query.state || info.state) as string;
    else
      return res.redirect('/');
    
    // info exists and is not empty
    if (info && Object.keys(info).length > 0) {
      console.log("[OIDC] Info: ", info);
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
      console.log('[OIDC] User logged in', user.username, 'with RHID:', req.session.rhid);
      const authorised = await sessionDatabase.authoriseLoginSession(user.username, req.session.rhid || info.state);
      if (authorised)
        return res.redirect('/user');
      else
        return res.redirect('/');
    
    });

  }) (req, res, next);
});

module.exports = { oauth2 };