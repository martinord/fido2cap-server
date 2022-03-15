import type { AuthenticatorDevice } from '@simplewebauthn/typescript-types';
import mongoose from 'mongoose';

export class User {
  
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
  isLoggedIn?: Boolean;
  isAdmin?: Boolean;
  
  constructor(id : string, username : string) {
    this.id = id;
    this.username = username;
    this.devices = [];
    this.isLoggedIn = false;
    this.isAdmin = false;
  }
}

const deviceSchema: mongoose.Schema = new mongoose.Schema({
  credentialPublicKey: Buffer,
  credentialID: Buffer,
  counter: Number,
  transports: [String],
});

const userSchema: mongoose.Schema = new mongoose.Schema({
  id: { type: String, unique: true },
  username: String,
  devices: [deviceSchema],
  isLoggedIn: { type: Boolean, default: false },
  isAdmin: { type: Boolean, default: false }
});

export const UserModel = mongoose.model('User', userSchema);

export declare type RegisteredUser = {
  username?: string,
  nofdevices?: number,
  isLoggedIn?: boolean
};

module.exports = { User, UserModel };