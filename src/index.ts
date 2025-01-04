import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import { v4 as uuidv4 } from "uuid";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

// Initialize PostgreSQL Pool
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

// Initialize Express app
const app = express();
app.use(express.json());
app.use(
    cors({
        origin: "https://niklaskaulfers.github.io",
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Authorization", "Content-Type"],
    })
);

// Helper Functions
const generateRandomId = (): string => uuidv4();

const verifyPassword = async (inputPassword: string, storedPassword: string): Promise<boolean> => {
    return bcrypt.compare(inputPassword, storedPassword);
};

// REST API Endpoints
app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
});

app.post("/api/message", (req: Request, res: Response) => {
    const { message, user } = req.body;

    if (!message || !user) {
        res.status(400).json({ error: "Message and user are required." });
        return;
    }

    server.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ user, message }));
        }
    });

    res.status(200).json({ message: "Message broadcasted to WebSocket clients." });
});

app.post("/api/users", async (req: Request, res: Response) => {
    const { user, email, password } = req.body;

    if (!user || !email || !password) {
        res.status(400).json({ error: "User, email, and password are required." });
        return;
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query("INSERT INTO users (id, email, pin) VALUES ($1, $2, $3)", [user, email, hashedPassword]);
        res.status(201).json({ message: `User ${user} has been created.` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Something went wrong with the database." });
    }
});

app.get("/api/users/:user", async (req: Request, res: Response): Promise<void> => {
    const { user } = req.params;

    try {
        const result = await pool.query("SELECT id, email FROM users WHERE id = $1", [user]);
        if (result.rows.length > 0) {
            res.status(200).json({ user: result.rows[0] });
        } else {
            res.status(404).json({ error: "User not found." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

app.post("/api/login", async (req: Request, res: Response): Promise<void> => {
    const { username, password } = req.body;

    if (!username || !password) {
        res.status(400).json({ error: "Username and password are required." });
        return;
    }

    try {
        const result = await pool.query("SELECT id, pin FROM users WHERE id = $1", [username]);
        if (result.rows.length === 0) {
            res.status(404).json({ error: "No user found." });
            return;
        }

        const user = result.rows[0];
        const passwordMatch = await verifyPassword(password, user.pin);

        if (!passwordMatch) {
            res.status(403).json({ error: "Invalid password." });
            return;
        }

        res.status(200).json({ message: `Logged in as ${username}` });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

app.post("/api/rooms", async (req: Request, res: Response): Promise<void> => {
    const { pin, userID, userPin } = req.body;
    const roomId = generateRandomId();

    if (!userID || !userPin) {
        res.status(400).json({ error: "User ID and PIN are required." });
        return;
    }

    try {
        const userResult = await pool.query("SELECT id, pin FROM users WHERE id = $1", [userID]);
        if (userResult.rows.length === 0) {
            res.status(404).json({ error: "User not found." });
            return;
        }

        const user = userResult.rows[0];
        const passwordMatch = await verifyPassword(userPin, user.pin);

        if (!passwordMatch) {
            res.status(403).json({ error: "Invalid user credentials." });
            return;
        }

        if (!pin) {
            await pool.query("INSERT INTO Rooms (id, creator) VALUES ($1, $2)", [roomId, userID]);
        } else {
            const hashedPassword = await bcrypt.hash(pin, 10);
            await pool.query("INSERT INTO Rooms (id, pin, creator) VALUES ($1, $2, $3)", [roomId, hashedPassword, userID]);
        }

        res.status(201).json({ message: "Room created successfully", roomId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error." });
    }
});

app.get("/api/rooms/:roomId", async (req: Request, res: Response): Promise<void> => {
    const { roomId } = req.params;

    try {
        const result = await pool.query("SELECT id, pin, creator FROM Rooms WHERE id = $1", [roomId]);
        if (result.rows.length > 0) {
            res.status(200).json({ room: result.rows[0] });
        } else {
            res.status(404).json({ error: "Room not found." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

// Create HTTP and WebSocket Servers
const httpServer = http.createServer(app);
const server = new WebSocket.Server({ server: httpServer });

server.on("connection", (socket: ExtendedWebSocket) => {
    socket.id = generateRandomId();
    socket.isAlive = true;

    console.log(`Client connected: ${socket.id}`);

    socket.on("message", (message: string) => {
        console.log(`Received message from ${socket.id}: ${message}`);
        server.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN && client !== socket) {
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

    socket.send(JSON.stringify({ user: "Server", message: "Welcome to WebSocket!" }));
});

setInterval(() => {
    server.clients.forEach((client) => {
        const ws = client as ExtendedWebSocket;
        if (!ws.isAlive) {
            console.log(`Terminating inactive client: ${ws.id}`);
            return client.terminate();
        }
        ws.isAlive = false;
        client.ping();
    });
}, 30000);

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});