import {BackendError} from "./backend-error";
import {Response} from "express";

const message: string = "Server Error";
const errorCode: number = 500;

export class DefaultServerError extends BackendError {

    constructor() {
       super(message, errorCode)
    }

    static toResponse(res: Response): Response {
        return res.status(errorCode).json({message: message});
    }
}