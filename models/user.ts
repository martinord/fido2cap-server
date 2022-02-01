import type { AuthenticatorDevice } from '@simplewebauthn/typescript-types';
import mongoose from 'mongoose';

/**
 * You'll need a database to store a few things:
 *
 * 1. Users
 *
 * You'll need to be able to associate registration and authentications challenges, and
 * authenticators to a specific user. See `LoggedInUser` below for an idea of the minimum amount of
 * info you'll need to track for a specific user during these flows.
 *
 * 2. Challenges
 *
 * The totally-random-unique-every-time values you pass into every execution of
 * `generateRegistrationOptions()` or `generateAuthenticationOptions()` MUST be stored until
 * `verifyRegistrationResponse()` or `verifyAuthenticationResponse()` (respectively) is called to verify
 * that the response contains the signed challenge.
 *
 * These values only need to be persisted for `timeout` number of milliseconds (see the `generate`
 * methods and their optional `timeout` parameter)
 *
 * 3. Authenticator Devices
 *
 * After registration, you'll need to store three things about the authenticator:
 *
 * - Base64-encoded "Credential ID" (varchar)
 * - Base64-encoded "Public Key" (varchar)
 * - Counter (int)
 *
 * Each authenticator must also be associated to a user so that you can generate a list of
 * authenticator credential IDs to pass into `generateAuthenticationOptions()`, from which one is
 * expected to generate an authentication response.
 */
export class User {
  
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
  currentChallenge?: string; // TODO: MongoDB Schema delete challenge after 6000ms
  
  constructor(id : string, username : string) {
    this.id = id;
    this.username = username;
    this.devices = [];
    this.currentChallenge = '';
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
  currentChallenge: { type: String, default: '', expires: '6000ms'} // TODO: MongoDB Schema delete challenge after 6000ms
});

export const UserModel = mongoose.model('User', userSchema);

module.exports = { User, UserModel };