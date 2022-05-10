import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

const { SESSION_EXPIRE_TIME } = process.env;

export class Session {
  
  userId: string;
  rhid: string | undefined;
  fasAuthentication: boolean;
  gatewayHash: string | undefined;
  
  constructor(userId: string, gatewayHash: string | undefined) {
    this.userId = userId;
    this.rhid = "";
    this.fasAuthentication = false;
    this.gatewayHash = gatewayHash;
  }
  
}

class SessionDatabase {

  sessionModel: mongoose.Model<Session>;

  constructor(model : mongoose.Model<Session>){
    this.sessionModel = model;
  }

  /**
   * Get session by user ID
   */
  public async getByUserId( userId : string | undefined ) : Promise<Session[]> {
    return (await this.sessionModel.find({ userId: userId }) as unknown) as Session[];
  }

  /**
   * Clear all sessions by GatewayHash
   */
  public async clearGatewaySessions( gatewayHash : string ) {
    await this.sessionModel.deleteMany({ gatewayHash: gatewayHash });
  }

  /**
   * Get unauthenticated gateway sessions by GatewayHash
   */
  public async getUnauthenticatedGatewaySessions( gatewayHash : string ) : Promise<Session[]> {
    return (await this.sessionModel.find({ gatewayHash: gatewayHash, fasAuthentication: false }) as unknown) as Session[];
  }

  /**
   * Mark session as authenticated in the gateway by GatewayHash
   */
  public async markAuthenticatedGatewaySession( gatewayHash : string, rhid : string) {
    await this.sessionModel.updateOne({ gatewayHash: gatewayHash, rhid: rhid }, { $set: { fasAuthentication: true } });
  }

  /**
   * Logout user by sessionId
   */
  public async logoutSession( sessionId: string | undefined ) {
    if ( sessionId && (sessionId != "")) {
        await this.sessionModel.findByIdAndDelete( new mongoose.Types.ObjectId(sessionId) ); 
    }
  }

  public async loginSession( loggedUserId: string | undefined, rhid: string | undefined, gatewayHash: string | undefined ) : Promise<string> {
    if (loggedUserId && (loggedUserId != "")) {
        await this.sessionModel.createCollection();
        const session_db = new this.sessionModel({ 
          userId: loggedUserId,
          rhid: rhid,
          fasAuthentication: false,
          gatewayHash: gatewayHash
        });
        const document = await session_db.save();
        return document.id;
    }
    return "";
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
  gatewayHash: String,
  fasAuthentication: { 
    type: Boolean,
    default: false
    // Determines if it was already authenticated by OpenNDS Authmon
  }
});

export const sessionDatabase = new SessionDatabase(mongoose.model('Session', sessionSchema));

module.exports = { Session, sessionDatabase };