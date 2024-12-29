import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, { Request, Response, NextFunction } from "express";

// Extend WebSocket to track client state
interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

// Initialize Express app
const app = express();
app.use(express.json());

// PostgreSQL connection pool
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

// WebSocket server setup
const httpServer = http.createServer(app);
const server = new WebSocket.Server({ server: httpServer });

const PORT = process.env.PORT || 8080;

// REST API Endpoint to check status
app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
});

// REST API Endpoint to create a user
app.post("/api/users", (req: Request, res: Response) => {
    const { user, email, password } = req.body;

    // Basic validation
    if (!user || user.length <= 3 || !password || password.length <= 3) {
        return res.status(400).json({
            error: "Invalid username or password. Must be at least 3 characters long.",
        });
    }

    // Establish connection to PostgreSQL
    const client = new pg.Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    });

    client.connect((err) => {
        if (err) {
            console.error("Failed to connect to PostgreSQL:", err.message);
            return res.status(500).json({ error: "Database connection failed." });
        }

        const query = email
            ? "INSERT INTO users (id, email, pin) VALUES ($1, $2, $3)"
            : "INSERT INTO users (id, pin) VALUES ($1, $2)";
        const params = email ? [user, email, password] : [user, password];

        // Execute the query
        client.query(query, params, (queryErr) => {
            client.end(); // Close the connection
            if (queryErr) {
                console.error("Error executing query:", queryErr.message);
                return res.status(500).json({ error: "Failed to create user." });
            }

            res.status(201).json({ message: `User ${user} created successfully.` });
        });
    });
});

// Get user info from the database
app.get("/api/users/:user", (req: Request, res: Response) => {
    const client = new pg.Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false },
    });

    const userToFind = req.params.user;

    client.connect((err) => {
        if (err) {
            console.error("Failed to connect to PostgreSQL:", err.message);
            return res.status(500).json({ error: "Database connection failed." });
        }

        client.query(
            "SELECT id, email FROM users WHERE id = $1",
            [userToFind],
            (queryErr, result) => {
                client.end(); // Close the connection
                if (queryErr) {
                    console.error("Error executing query:", queryErr.message);
                    return res.status(500).json({ error: "Failed to fetch user." });
                }

                if (result.rows.length === 0) {
                    return res.status(404).json({ error: "User not found." });
                }

                res.status(200).json(result.rows[0]);
            }
        );
    });
});

// WebSocket connection management
server.on("connection", (socket: ExtendedWebSocket) => {
    socket.id = generateClientId();
    socket.isAlive = true;

    console.log(`Client connected: ${socket.id}`);

    // Respond to incoming WebSocket messages
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

    // Send a welcome message to the newly connected client
    socket.send(JSON.stringify({ user: "Server", message: "Welcome to WebSocket!" }));
});

// Periodically ping clients to ensure they are alive
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

// Function to generate a unique client ID
function generateClientId() {
    return Math.random().toString(36).substr(2, 9);
}

// Start the server
httpServer.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
