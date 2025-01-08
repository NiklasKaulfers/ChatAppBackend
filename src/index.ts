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

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || !process.env.DATABASE_URL){
    console.error("JWT Secret Key Mssing")
    throw new Error("JWT Secret Key missing");
}
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
    origin: "https://chat-app-iib23-frontend-47fb2c785a51.herokuapp.com",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"],
    optionsSuccessStatus: 200,
}));


app.options("*", cors());

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
/*


            API Endpoint


 */



app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
});


//users


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

//login

app.post("/api/login", async (req: Request, res: Response): Promise<void> => {
    const username = req.body.username;
    const password = req.body.password;

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

        res.status(200).json({ message: `Logged in as ${username}`, accessToken: accessToken, refreshToken: refreshToken });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
});

// token


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

// rooms


app.post("/api/rooms", async (req: Request, res: Response): Promise<void> => {
    const { pin, display_name } = req.body;
    const roomId = generateRandomId();


    try {
        const token = req.headers["authorization"]?.split(" ")[1];

        if (!token) {
            res.status(400).json({ error: "Authorization token is required." })
            return;
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET) as { id: string };
            let userId = decoded.id;


            const userResult = await pool.query("SELECT id FROM users WHERE id = $1", [userId]);
            console.log(userResult);
            if (userResult.rows.length === 0) {
                res.status(404).json({ error: "User not found." });
                return;
            } else {
                userId = userResult.rows[0].id;
            }

            if (!pin) {
                await pool.query("INSERT INTO Rooms (id, display_name, creator) VALUES ($1, $3, $2)"
                    , [roomId, display_name, userId]);
            } else {
                const hashedPassword = await bcrypt.hash(pin, 10);
                await pool.query("INSERT INTO Rooms (id, display_name, pin, creator) VALUES ($1, $2, $3, $4)"
                    , [roomId, display_name, hashedPassword, userId]);
            }

            res.status(201).json({ message: `Room ${roomId} created with display name ${display_name}.` });

        } catch (err) {
            console.error(err);
            res.status(403).json({ error: "Invalid or expired token." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Internal server error." });
    }
});

app.get("/api/rooms", async (req: Request, res: Response): Promise<void> => {
    try {
        const rooms = await pool.query(
            "Select id,display_name, creator, case when pin is null then 'False' else 'True' end as has_password from rooms"
        );

        if (!rooms) {
            res.status(200).json({ message: "No rooms found.", ids: [] });
            return;
        }

        res.status(200).json({ rooms: rooms.rows });
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


// server

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
