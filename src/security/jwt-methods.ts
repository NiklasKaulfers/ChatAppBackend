import jwt from "jsonwebtoken";


interface GenerateTokenInput  {
    userId: string;
    expiry: string;
    jwtSecret: string;
}

export const generateAccessToken = (input: GenerateTokenInput): string => {
    return jwt.sign({ id: input.userId }, input.jwtSecret, { expiresIn: input.expiry });
};

export const generateRefreshToken = (input: GenerateTokenInput): string => {
    return jwt.sign({ id: input.userId }, input.jwtSecret, { expiresIn: input.expiry });
};