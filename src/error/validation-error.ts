import {BackendError} from "./backend-error";

export class ValidationError extends BackendError {
    constructor(message: string, errorCode: number) {
        super(message, errorCode);
    }
}