import {BackendError} from "./backend-error";

export class JwtError extends BackendError {
    constructor(message: string, errorCode: number) {
        super(message, errorCode);
    }
}