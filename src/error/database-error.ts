import {BackendError} from "./backend-error";

export class DatabaseError extends BackendError {
    constructor(public message: string, errorCode: number) {
        super(message, errorCode);
    }
}