import {BackendError} from "./BackendError";

export class DatabaseError extends BackendError {
    constructor(public message: string, errorCode: number) {
        super(message, errorCode);
    }
}