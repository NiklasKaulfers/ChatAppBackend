import jwt from "jsonwebtoken";
import {JwtError} from "../error/jwt-error";

const JWT_SECRET = process.env.JWT_SECRET!;

const ACCESS_TOKEN_EXPIRY = "2h";
const REFRESH_TOKEN_EXPIRY = "7d";


export const generateAccessToken = (userId: string): string => {
    return jwt.sign({id: userId}, JWT_SECRET, {expiresIn: ACCESS_TOKEN_EXPIRY});
};

export const generateRefreshToken = (userId: string): string => {
    return jwt.sign({id: userId}, JWT_SECRET, {expiresIn: REFRESH_TOKEN_EXPIRY});
};

export function verifyJWT<T>(auth: string): T{
    try{
        return jwt.verify(auth, JWT_SECRET) as T;
    } catch(error: any){
        throw new JwtError(error.message, 403)
    }
}
