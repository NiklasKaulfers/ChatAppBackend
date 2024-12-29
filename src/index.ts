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
    const client = new pg.Client({
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });
    const newUser:string = JSON.stringify(req.body["user"]);
    const newUserEmail:string = JSON.stringify(req.body["email"]);
    const newUserPassword:string = JSON.stringify(req.body["password"]);
    try {
        const connectedToPg: () => Promise<void> = async (): Promise<void> => await client.connect();
        if (!connectedToPg) {
            res.status(400).json({ error: "Postgres not connected" });
        }
        if (!newUser || !newUserPassword) {
            throw new Error("Invalid user email address or username.");
        }
        if (!newUserEmail) {
            client.query("INSERT INTO users (id, pin) values ('" + newUser + "','" + newUserPassword + "')", (err, result) =>{
                if (err) throw err;
                const disconnect: ()=>Promise<void> = async (): Promise<void> => await client.end();
                if (!disconnect) {
                    res.status(400).json({ error: "Postgres is having issues" });
                }
            });

        } else {
            client.query("INSERT INTO users (id, email, pin) values ('" + newUser + "','" + newUserEmail + "','" + newUserPassword + "')", (err, result) => {
                if (err) throw err;
                const disconnect: () => Promise<void> = async (): Promise<void> => await client.end();
                if (!disconnect) {
                    res.status(400).json({error: "Postgres is having issues"});
                }
            });
        }
    } catch (err){
        console.error(err);
        res.status(500).json({
            message: "Something went wrong with postgres.",
        })
    }
    res.status(200).json({ message: `User ${newUser} has been created.` });
})

app.get("/api/users/:user", (req: Request, res: Response) => {
    const client = new pg.Client({
        connectionString: process.env.DATABASE_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });

    // Access user from the URL parameter
    const userToFind = req.params.user;

    if (userToFind) {
        client.query("SELECT id, email FROM users WHERE id = $1", [userToFind], (err, result) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: "Database error occurred." });
            }

            if (result.rows.length > 0) {
                // Send back user details
                res.status(200).json({ message: `User found: ${JSON.stringify(result.rows[0])}` });
            } else {
                res.status(404).json({ error: "User not found." });
            }

            // Close the connection
            client.end();
        });
    } else {
        res.status(400).json({ error: "Missing user parameter." });
    }
});



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
   serverOnConnection(socket);
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

function serverOnConnection(socket: ExtendedWebSocket) {
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
}