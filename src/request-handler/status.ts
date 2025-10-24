import * as express from "express";


export default function status(app: any){
    app.get("/api/status", (req: express.Request, res: express.Response): void => {
        res.json({
            statusText:"Server is running",
            status: 200
        });
    });
}


