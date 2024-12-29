import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, {Request, Response} from "express";
import bcrypt from "bcryptjs";  // For password hashing
import jwt from "jsonwebtoken";
import cors from "cors";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});
// Initialize Express app
const app = express();

app.use(express.json());
app.use(cors({
    origin: "https://niklaskaulfers.github.io",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type"]
}));

// Define a REST API endpoint
app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running", connectedClients: server.clients.size });
});

app.post("/api/message", (req: Request, res: Response) => {
    const { message } = req.body["message"];
    const user:string = JSON.stringify(req.body["user"]);

    // Broadcast the message to all WebSocket clients
    server.clients.forEach((client) => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(JSON.stringify({ user: user, message }));
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
    const hashedPassword:(newUserPassword) => Promise<string>  =async (newUserPassword) => {
        return await bcrypt.hash(newUserPassword, 10);
    }
    try {
        const connectedToPg: () => Promise<void> = async (): Promise<void> => await client.connect();
        if (!connectedToPg) {
            res.status(400).json({ error: "Postgres not connected" });
        }
        if (!newUser || !newUserPassword) {
            throw new Error("Invalid user email address or username.");
        }
        if (!newUserEmail) {
            client.query("INSERT INTO users (id, pin) values ('" + newUser + "','" + hashedPassword + "')", (err, result) =>{
                if (err) throw err;
                const disconnect: ()=>Promise<void> = async (): Promise<void> => await client.end();
                if (!disconnect) {
                    res.status(400).json({ error: "Postgres is having issues" });
                }
            });

        } else {
            client.query("INSERT INTO users (id, email, pin) values ('" + newUser + "','" + newUserEmail + "','" + hashedPassword + "')", (err, result) => {
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

app.get("/api/users/:user", (req: Request, res: Response):void => {
    const userToFind = req.params.user;

    if (!userToFind) {
        res.status(400).json({ error: "Missing user parameter." });
        return;
    }

    // Use parameterized query to prevent SQL injection
    pool.query("SELECT id, email FROM users WHERE id = $1", [userToFind], (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "Database error occurred." });
            return;
        }

        if (result.rows.length > 0) {
            res.status(200).json({ message: `User found: ${JSON.stringify(result.rows[0])}` });
        } else {
            res.status(404).json({ error: "User not found." });
        }
    });
});

// Helper function to compare passwords
const verifyPassword = async (inputPassword: string, storedPassword: string): Promise<boolean> => {
    return await bcrypt.compare(inputPassword, storedPassword);
};

// Login API: POST /api/login
app.post("/api/login", (req: Request, res: Response) => {
    const { username, password } = req.body;

    // Validate input
    if (!username || !password) {
        res.status(400).json({ error: "Username and password are required." });
        return;
    }

    // Query the database to get the user
    pool.query("SELECT id, pin FROM users WHERE id = $1", [username], async (err, result) => {
        if (err) {
            console.error(err);
            res.status(500).json({ error: "Database error." });
            return;
        }

        if (result.rows.length === 0) {
            res.status(404).json({ error: "User not found." });
            return ;
        }

        const user = result.rows[0];

        // Verify password
        const passwordMatch = await verifyPassword(password, user.pin);

        if (!passwordMatch) {
            res.status(401).json({ error: "Incorrect password." });
            return ;
        }

        // Password is correct, generate JWT token
        const token = jwt.sign(
            { userId: user.id },  // Payload (user info in the token)
            process.env.JWT_SECRET || "your_jwt_secret",  // Secret key to sign the token
            { expiresIn: "1h" }  // Token expiration (e.g., 1 hour)
        );

        // Send back the success response with the token
        res.status(200).json({
            message: "Login successful.",
            token: token,
        });
    });
});

// Protect a route with JWT authentication
app.get("/api/protected", (req: Request, res: Response) => {
    const authHeader = req.headers["authorization"];

    if (!authHeader) {
        res.status(401).json({ error: "No token provided." });
        return ;
    }

    const token = authHeader.split(' ')[1]; // This will extract the token after "Bearer"

    if (!token) {
        res.status(401).json({ error: "Token missing or malformed." });
        return;
    }

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET || "your_jwt_secret", (err, decoded) => {
        if (err) {
            res.status(403).json({ error: "Invalid token." });
            return;
        }

        // Token is valid, send a protected response
        const { userId } = decoded as { userId: string };
        res.status(200).json({ message: `Welcome user ${userId}` });
        return ;
    });
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