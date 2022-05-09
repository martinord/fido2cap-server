import { UserModel } from '../models/user';

/**
 * Helper functions
 */
export async function generateRandomUserId(): Promise<string> {
    let outString: string = '';
    const inOptions: string = 'abcdefghijklmnopqrstuvwxyz0123456789';

    for (let i = 0; i < 32; i++) 
        outString += inOptions.charAt(Math.floor(Math.random() * inOptions.length));

    return (await UserModel.findOne({ id: outString })) ? generateRandomUserId() : outString;
}

export function isEmailAddress( text : string): boolean {
    const regexp = new RegExp(/^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/);

    return regexp.test(text);
}

export async function isAdministratorConfigured() : Promise<boolean> {
    return (await UserModel.find({ isAdmin: true }).count() > 0);
}