import {Response} from "express";

export class BackendError extends Error {
    errorCode: number;
    constructor(message: string, errorCode: number) {
        super(message);
        this.errorCode = errorCode;
    }

    toResponse(res: Response): Response {
        return res.status(this.errorCode).json({message: this.message});
    }
}