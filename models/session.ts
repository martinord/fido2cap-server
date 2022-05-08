import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const { ENABLE_HTTPS, SESSION_KEY, SESSION_EXPIRE_TIME } = process.env;

export class Session {
  
  userId: string;
  rhid: string;
  fasAuthentication: boolean;
  
  constructor(userId: string) {
    this.userId = userId;
    this.rhid = "";
    this.fasAuthentication = false;
  }
  
}

let sessionSchema: mongoose.Schema = new mongoose.Schema({
  expireAt: { 
    type: Date, 
    index: { 
      unique: false,
      expireAfterSeconds: 0 
    },
    // Expire time in minutes, set to 1h by default
    default: (new Date()).setSeconds((new Date()).getSeconds() + (+(SESSION_EXPIRE_TIME ?? 60) * 60)) },
  userId: String,
  rhid: String,
  fasAuthentication: { 
    type: Boolean,
    default: false
    // Determines if it was already authenticated by OpenNDS Authmon
  }
});

export const SessionModel = mongoose.model('Session', sessionSchema);

module.exports = { Session, SessionModel };