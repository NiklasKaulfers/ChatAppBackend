import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
const ACCESS_TOKEN_EXPIRY = "1h";
const REFRESH_TOKEN_EXPIRY = "7d";
const refreshTokens: Record<string, string> = {};

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

const app = express();
app.use(express.json());
app.use(cors({
    origin: "https://niklaskaulfers.github.io",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"],
}));

const generateRandomId = (): string => uuidv4();

const generateAccessToken = (userId: string): string => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

const generateRefreshToken = (userId: string): string => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
};

const verifyPassword = async (inputPassword: string, storedPassword: string): Promise<boolean> => {
    return bcrypt.compare(inputPassword, storedPassword);
};

app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
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

        const accessToken = generateAccessToken(user.id);
        const refreshToken = generateRefreshToken(user.id);
        refreshTokens[user.id] = refreshToken;

        res.status(200).json({ message: `Logged in as ${username}`, accessToken, refreshToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

app.post("/api/tokenRefresh", (req: Request, res: Response): void => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        res.status(400).json({ error: "Refresh token is required." });
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET) as { id: string };
        const userId = decoded.id;

        if (refreshTokens[userId] !== refreshToken) {
            res.status(403).json({ error: "Invalid or expired refresh token." });
            return;
        }

        const newAccessToken = generateAccessToken(userId);
        res.status(200).json({ message: "Token refreshed successfully", accessToken: newAccessToken });
    } catch (err) {
        console.error(err);
        res.status(403).json({ error: "Invalid or expired refresh token." });
    }
});

app.post("/api/logout", (req: Request, res: Response): void => {
    const { refreshToken } = req.body;

    if (!refreshToken) {
        res.status(400).json({ error: "Refresh token is required." });
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET) as { id: string };
        const userId = decoded.id;
        delete refreshTokens[userId];

        res.status(200).json({ message: "Logged out successfully." });
    } catch (err) {
        console.error(err);
        res.status(403).json({ error: "Invalid or expired refresh token." });
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

app.get("/api/rooms", async (req: Request, res: Response): Promise<void> => {
    try {
        const rooms = await pool.query("SELECT * FROM rooms");
        const ids: string[] = rooms.rows.map((room) => room.id);

        if (!ids.length) {
            res.status(200).json({ message: "No rooms found.", ids: [] });
            return;
        }

        res.status(200).json({ ids });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Database error occurred." });
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
