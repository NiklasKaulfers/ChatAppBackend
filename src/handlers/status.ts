import {Request, Response} from "express";
import {DatabaseHandler} from "../database-calls/database-handler";
import {DatabaseError} from "../error/database-error";
import {DefaultServerError} from "../error/default-server-error";

export async function handleStatusRequest(req: Request, res: Response): Promise<Response> {

    const handler = new DatabaseHandler();
    try {
        const data = await handler.checkLogs();
        return res.status(200).json(data);
    } catch (error: any) {
        if (error instanceof DatabaseError) {
            return error.toResponse(res);
        } else {
            return DefaultServerError.toResponse(res);
        }
    }
}