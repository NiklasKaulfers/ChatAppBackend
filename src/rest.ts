import express, {Express, Request, Response} from "express";



export const api = () =>{
    const port = process.env.PORT;
    const app: Express = express();

// Define the root path with a greeting message
    app.get("/", (req: Request, res: Response) => {
        res.json({message: "Welcome to the Express + TypeScript Server!"});
    });

// Start the Express server
    app.listen(port, () => {

    });
}