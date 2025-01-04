import * as WebSocket from "ws";
import * as http from "http";
import pg from "pg";
import express, {Request, Response} from "express";
import bcrypt from "bcryptjs";  // For password hashing
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
const client = new pg.Client({
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
app.post("/api/users", async (req: Request, res: Response) => {
    const user:string = req.body["user"];
    const email:string = req.body["email"];
    const password:string = req.body["password"];

    if (!user || !email || !password) {
        res.status(400).json({ error: "User, email, and password are required." });
        return;
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        await client.connect();

        // Insert the user into the database
        const query = `INSERT INTO users (id, email, pin) VALUES ($1, $2, $3)`;
        await client.query(query, [user, email, hashedPassword]);

        await client.end();

        res.status(200).json({ message: `User ${user} has been created.` });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Something went wrong with Postgres." });
    }
});


app.get("/api/users/:user", (req: Request, res: Response):void => {
    const userToFind = req.params.user;

    if (!userToFind) {
        res.status(400).json({ error: "Missing user parameter." });
        return;
    }

    // Use parameterized query to prevent SQL injection
    pool.query("SELECT id, email FROM users WHERE id = $1"
        , [userToFind], (err, result) => {
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


// Login API: POST /api/login
app.post("/api/login", (req: Request, res: Response) => {
    const { username, password } = req.body;
    if (!username || !password) {
        res.status(400).json({ error: "Missing username or password parameter." });
        return;
    }
    pool.query("SELECT id, pin FROM users WHERE id = $1", [username]
        , async (err, result) => {
            if (err) {
                console.error(err);
               res.status(500).json({ error: "Database error occurred." });
               return;
            }

            if (result.rows.length === 0) {
                res.status(404).json({ error: "No user found." });
                return;
            }

            const user = result.rows[0];

            // Verify password
            const passwordMatch = await verifyPassword(password, user.pin);
            if (!passwordMatch) {
                res.status(404).json({ error: "Invalid password" });
                return;
            }
            res.status(200).json({ "user": user, message: `Logged in as ${user}` });
    // Validate input
    if (!username || !password) {
        res.status(400).json({ error: "Username and password are required." });
        return;
    }
})
});

app.post("/api/rooms", (req: Request, res: Response) => {
    const roomId = generateClientId();
    const pin= req.body["pin"];
    const userID = req.body["userID"];
    const userPin = req.body["userPin"];

    try {
        if (!userID || !userPin) {
            res.status(400).json({error: "Missing user parameter."});
            return;
        }
        pool.query("SELECT id, pin FROM users WHERE id = $1", [userID]
            , async (err, result) => {
                if (err) {
                    console.error(err);
                    res.status(500).json({error: "Database error occurred."});
                    return;
                }

                if (result.rows.length === 0) {
                    res.status(404).json({error: "No user found."});
                    return;
                }

                const user = result.rows[0];

                // Verify password
                const passwordMatch = await verifyPassword(userPin, user.pin);
                if (!passwordMatch) {
                    res.status(404).json({error: "Invalid password"});
                    return;
                }
                // Validate input
                if (!userID || !userPin) {
                    res.status(400).json({error: "Username and password are required."});
                    return;
                }
            });
    } catch (error) {
    console.error(error);
    res.status(500).json({error: "Database error occurred."});
    }
    if (!pin || pin === "") {
        try {
            client.connect();
            client.query("INSERT INTO Rooms (id, creator) VALUES ($1, $2)", [roomId, userID]);
            client.end();
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: "Error creating the room." });
        }
    } else {
        const hashedPassword = bcrypt.hash(pin, 10);
        if (!hashedPassword) {
            res.status(400).json({ error: "Error storing the password." });
            return;
        }
        try {
            client.connect();
            client.query("INSERT INTO Rooms (id, pin, creator) VALUES ($1, $2, $3)", [roomId, hashedPassword, userID]);
            client.end();
        } catch (err) {
            console.error(err);
            res.status(400).json({ error: "Error creating the room." });
            return;
        }
    }

})
app.get("/api/rooms/:roomId", (req: Request, res: Response) => {
    const roomId: string = req.params.roomId;
   try{
       pool.query("SELECT (id, pin, creator) FROM Rooms WHERE id = $1", [roomId], (err, result) => {
           if (err) {
               console.error(err);
               res.status(500).json({ error: "Database error occurred." });
               return;
           }
           if (result.rows.length > 0) {
               res.status(200).json({ message: `Room found: ${JSON.stringify(result.rows[0])}` });
           } else {
               res.status(404).json({ error: "User not found." });
           }
       });
   } catch (e){
       console.error(e);
       res.status(400).json({ error: "Error getting room." });
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

const verifyPassword = async (inputPassword: string, storedPassword: string): Promise<boolean> => {
    return await bcrypt.compare(inputPassword, storedPassword);
};



// Function to generate unique IDs for WebSocket clients
const generateClientId = () => Math.random().toString(36).substring(2, 9);

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