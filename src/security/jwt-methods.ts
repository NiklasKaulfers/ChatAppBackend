import jwt from "jsonwebtoken";


interface GenerateTokenInput  {
    userId: string;
    expiry: string;
    jwtSecret: string;
}

const generateAccessToken = (input: GenerateTokenInput): string => {
    return jwt.sign({ id: input.userId }, input.jwtSecret, { expiresIn: input.expiry });
};

const generateRefreshToken = (input: GenerateTokenInput): string => {
    return jwt.sign({ id: input.userId }, input.jwtSecret, { expiresIn: input.expiry });
};