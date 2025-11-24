import {Response, Request} from "express";
import {ValidationError} from "../../error/validation-error";
import {DatabaseHandler} from "../../database-calls/database-handler";
import {UserId} from "../../objects/user";
import {verifyJWT} from "../../helpers/jwt-helper";
import {DefaultServerError} from "../../error/default-server-error";



export async function handleStatusRequest(req: Request, res: Response, databaseHandler: DatabaseHandler): Promise<Response> {
    try {
        const auth = validateHeader(req.headers.authorization?.split(" ")[1])

        const data = await databaseHandler.getUser(auth)

        return res.status(200).json({
            id: data[0].id,
            email: data[0].email
        });
    } catch (e){
        if (e instanceof ValidationError) {
            return e.toResponse(res);
        }
        return DefaultServerError.toResponse(res)
    }

}

function validateHeader(header: string | undefined): string {
    if (!header) throw new ValidationError("header is required", 403);
    verifyJWT<UserId>(header)
    return header;
}

