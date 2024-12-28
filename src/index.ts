import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, {Request, Response} from "express";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

// Initialize Express app
const app = express();

app.use(express.json());

// Define a REST API endpoint
app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
});

app.post("/api/message", (req: Request, res: Response) => {
    const { message } = req.body;

    // Broadcast the message to all WebSocket clients
    server.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ user: "API", message }));
        }
    });

    res.status(200).json({ message: "Message broadcasted to WebSocket clients." });
});


app.post("/api/users", (req: Request, res: Response) => {
    const client = new pg.Client();
    const newUser:string = JSON.parse(req.body.user);
    const newUserEmail:string = JSON.parse(req.body.email);
    const newUserPassword:string = JSON.parse(req.body.password);
    try {
        const connectedToPg = async () => await client.connect();
        if (!connectedToPg) {
            res.status(400).json({ error: "Postgres not connected" });
        }
        client.query('INSERT INTO users (id, email, pin) values (' + newUser + "," + newUserEmail + "," + newUserPassword + ")");
    } catch (err){
        console.error(err);
        res.status(500).json({
            message: "Something went wrong with postgres.",
        })
    } finally {
        const disconnect = async () => await client.end();
        if (!disconnect) {
            res.status(400).json({ error: "Postgres is having issues" });
        }
    }
    res.status(200).json({ message: `User ${newUser} has been created.` });
})

// Create the HTTP server
const httpServer = http.createServer(app);

// Create the WebSocket server
const server = new WebSocket.Server({ server: httpServer });

const PORT = process.env.PORT || 8080;

httpServer.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});

// Function to generate unique IDs for WebSocket clients
const generateClientId = () => Math.random().toString(36).substr(2, 9);

// Handle WebSocket connections
server.on("connection", (socket: ExtendedWebSocket) => {
    socket.id = generateClientId();
    socket.isAlive = true;

    console.log(`Client connected: ${socket.id}`);

    // Respond to WebSocket messages
    socket.on("message", (message: string) => {
        console.log(`Received message from ${socket.id}: ${message}`);

        // Broadcast the message to all connected clients
        server.clients.forEach((client) => {
            if (client !== socket && client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({ user: socket.id, message }));
            }
        });
    });

    socket.on("pong", () => {
        socket.isAlive = true;
    });

    socket.on("close", () => {
        console.log(`Client disconnected: ${socket.id}`);
    });

    socket.on("error", (error: Error) => {
        console.error(`WebSocket error: ${error.message}`);
    });

    socket.send(JSON.stringify({ user: "Server", message: "Welcome to WebSocket!" }));
});

// Periodically ping clients to ensure they're alive
setInterval(() => {
    server.clients.forEach((client) => {
        const extendedClient = client as ExtendedWebSocket;
        if (!extendedClient.isAlive) {
            console.log(`Terminating inactive client: ${extendedClient.id}`);
            return client.terminate();
        }
        extendedClient.isAlive = false;
        client.ping();
    });
}, 30000);
