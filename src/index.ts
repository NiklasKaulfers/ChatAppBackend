import express, { Request, Response } from "express";
import {config, configDotenv} from "dotenv";

// Backend app with node.js, express.js and typescript


// Create a new express application instance
const app = express();

configDotenv()

// Set the network port
const port = 80;

// Define the root path with a greeting message
app.get("/", (req: Request, res: Response) => {
    res.json({ message: "Welcome to the Express + TypeScript Server!" });
});

// Start the Express server
app.listen(port, () => {
    console.log(`The server is running at http://localhost:${port}`);
});