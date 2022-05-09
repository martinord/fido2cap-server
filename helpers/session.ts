import { SessionModel } from '../models/session';
import mongoose from 'mongoose';

/**
 * Session helpers
 */
export async function logout(sessionId: string | undefined) {
    if ( sessionId && (sessionId != "")) {
        await SessionModel.findByIdAndDelete( new mongoose.Types.ObjectId(sessionId) ); 
    }
}

export async function login(loggedUserId: string | undefined, rhid: string | undefined, gatewayHash: string | undefined) : Promise<string> {
    if (loggedUserId && (loggedUserId != "")) {
        await SessionModel.createCollection();
        const session_db = new SessionModel({ userId: loggedUserId, rhid: rhid, gatewayHash: gatewayHash });
        const document = await session_db.save();
        return document.id;
    }
    return "";
}