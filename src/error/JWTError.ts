import {BackendError} from "./BackendError";

export class JWTError extends BackendError {
    constructor(message: string, errorCode: number) {
        super(message, errorCode);
    }


}