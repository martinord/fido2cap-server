import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const { ENABLE_HTTPS, SESSION_KEY, SESSION_EXPIRE_TIME } = process.env;

let sessionSchema: mongoose.Schema = new mongoose.Schema({
  createdAt: { 
    type: Date, 
    index: { 
      unique: true,
      // Expire time set to 1h by default
      expireAfterSeconds: (SESSION_EXPIRE_TIME ?? 3600) as number 
    }, 
    default: Date.now
  },
  userId: String
});

export const SessionModel = mongoose.model('Session', sessionSchema);

module.exports = { SessionModel };