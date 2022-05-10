import type { AuthenticatorDevice } from '@simplewebauthn/typescript-types';
import mongoose from 'mongoose';
import { sessionDatabase } from './session';

export class User {
  
  id: string;
  username: string;
  devices: AuthenticatorDevice[];
  isAdmin?: Boolean;
  
  constructor(id : string, username : string) {
    this.id = id;
    this.username = username;
    this.devices = [];
    this.isAdmin = false;
  }
}

class UserDatabase {

  userModel: mongoose.Model<User>;

  constructor(model : mongoose.Model<User>){
    this.userModel = model;
  }

  /**
   * Get all users
   */
  public async getRegisteredUsers() : Promise<RegisteredUser[]> {

    var users : User[] = (await this.userModel.find() as unknown) as User[];

    return await Promise.all(users.map( async (user) => (
      {
        username: user.username,
        nofdevices: user.devices.length,
        activesessions: (await sessionDatabase.getByUserId(user.id)).length
      }
    )));
  }

  /**
   * Get user by username
   */
  public async getByUsername( username : string | undefined ) : Promise<User> {
    return (await this.userModel.findOne({username: username}) as unknown) as User;
  }

  /**
   * Get user by user ID
   */
  public async getById( id : string | undefined ) : Promise<User> {
    return (await this.userModel.findOne({id: id}) as unknown) as User;
  }

  /**
   * Add a new user to the database 
   */
  public async registerNewUser( userId: string, username: string, device : AuthenticatorDevice ){
    this.userModel.createCollection().then( async () => {
        const user_db = new this.userModel({
          id: userId,
          username: username,
          devices: [ device ]
        });
        user_db.save();
    })
  }

  /**
   * Add an authenticator device to user
   */
  public async addDeviceToUser( userId: string, username: string, newDevice : AuthenticatorDevice ) {

    var user : User = await this.getByUsername(username);
    if (user) {
      // Check if the device is already registered
      const existingDevice = user.devices.find(device => device.credentialID === newDevice.credentialID);

      if (!existingDevice) {
          user.devices.push(newDevice);

          await this.userModel.updateOne({ id: user.id }, { $set: { devices: user.devices } });
      }
    } else {
        // Create new user if it does not already exist
        await this.registerNewUser(userId, username, newDevice);
        
    }
  }

  /**
   * Generate a new random user id
   */
  public async generateRandomUserId(): Promise<string> {
    let outString: string = '';
    const inOptions: string = 'abcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < 32; i++) 
        outString += inOptions.charAt(Math.floor(Math.random() * inOptions.length));

    return (await this.userModel.findOne({ id: outString })) ? this.generateRandomUserId() : outString;
  }

  /**
   * Checks if at least one administrator is registered
   */
  public async isAdministratorConfigured() : Promise<boolean> {
    return (await this.userModel.find({ isAdmin: true }).count() > 0);
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
  isAdmin: { type: Boolean, default: false }
});

export const userDatabase = new UserDatabase(mongoose.model('User', userSchema));

export declare type RegisteredUser = {
  username?: string,
  nofdevices?: number,
  activesessions?: number
};

module.exports = { User, userDatabase };