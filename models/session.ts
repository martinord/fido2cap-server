import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const { ENABLE_HTTPS, SESSION_KEY, SESSION_EXPIRE_TIME } = process.env;

let sessionSchema: mongoose.Schema = new mongoose.Schema({
  expireAt: { 
    type: Date, 
    index: { 
      unique: false,
      expireAfterSeconds: 0 
    },
    // Expire time set to 1h by default
    default: (new Date()).setSeconds((new Date()).getSeconds() + (+(SESSION_EXPIRE_TIME ?? 3600))) },
  userId: String
});

export const SessionModel = mongoose.model('Session', sessionSchema);

module.exports = { SessionModel };