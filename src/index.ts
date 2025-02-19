import * as WebSocket from "ws";
import pg from "pg";
import express, { Request, Response } from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import { v4 as uuidV4 } from "uuid";
import { Amplify } from 'aws-amplify';
import { events } from 'aws-amplify/data';
import {checkValidCharsForDB} from "./check-valid-chars-for-db";
import {Server} from "socket.io";
import {createServer} from "node:https";
import Mailjet from "node-mailjet";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string;
}

const ROOM_SECRET_KEY = process.env.ROOM_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const HANDSHAKE_KEY = process.env.HANDSHAKE_KEY;
if (!JWT_SECRET
    || !process.env.DATABASE_URL
    || !ROOM_SECRET_KEY
    || !process.env.AWS_ENDPOINT
    || !process.env.AWS_API_KEY
    || !HANDSHAKE_KEY) {
    console.error("At least 1 missing secret")
    throw new Error("Secrets are missing.");
}

// Amplify for AWS Appsync
Amplify.configure({
    "API": {
        "Events": {
            "endpoint": process.env.AWS_ENDPOINT,
            "region": "eu-central-1",
            "defaultAuthMode": "apiKey",
            "apiKey": process.env.AWS_API_KEY,
        }
    }
});

const ACCESS_TOKEN_EXPIRY = "2h";
const REFRESH_TOKEN_EXPIRY = "7d";
const ROOM_SECRET_EXPIRY = "2h";
// todo: this bad bad, add to db eventually
const refreshTokens: Record<string, string> = {};

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
});

const app = express();
app.use(express.json());
app.use(cors({
    origin: ["https://chat-app-iib23-frontend-47fb2c785a51.herokuapp.com", "https://chat-app-angular-dbba048e2d37.herokuapp.com" , process.env.AWS_ENDPOINT],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Authorization", "Content-Type", "Access-Control-Allow-Origin"],
    credentials: true,
    optionsSuccessStatus: 200,
}));


app.options("*", cors());

const generateRandomId = (): string => uuidV4();

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


            API Endpoints


 */



app.get("/api/status", (req: Request, res: Response): void => {
    res.json({ status: "Server is running"});
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


// verification to be used by lambda
// todo: should prop be options or smth
app.post("/api/rooms/verifyUser", async (req: Request, res: Response): Promise<void> => {
    const roomToken = req.body.roomtoken;
    const room = req.body.room;
    if (!roomToken) {
        res.status(400).json({ error: "Room token is required." });
        return;
    }
    const auth = jwt.verify(roomToken, JWT_SECRET) as {roomId: string, userId: string};
    if (auth && room === auth.roomId) {
        res.status(200).json({ message: "Successfully verified user." });
        return;
    }
    if (!auth){
        res.status(403).json({ error: "Invalid or expired token." });
    }
    if (room !== auth.roomId) {
        res.status(403).json({ error: "Verification not for this room." });
    }
})

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
        const token: string | undefined = req.headers.authorization?.split(" ")[1];

        if (!token) {
            res.status(400).json({ error: "Authorization token is required." })
            return;
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET) as { id: string };
            let userId = decoded.id;


            const userResult = await pool.query("SELECT id FROM users WHERE id = $1", [userId]);
            if (userResult.rows.length === 0) {
                res.status(404).json({ error: "User not found." });
                return;
            } else {
                userId = userResult.rows[0].id;
            }

            const allCharactersValid = checkValidCharsForDB(userId)
                && checkValidCharsForDB(display_name)
                && checkValidCharsForDB(roomId);
            if (!allCharactersValid) {
                res.status(403).json({ error: "Uses invalid characters." });
                return;
            }


            if (!pin) {
                await pool.query("INSERT INTO Rooms (id, display_name, creator) VALUES ($1, $2, $3)"
                    , [roomId, display_name, userId]);
            } else {
                const hashedPassword = await bcrypt.hash(pin, 10);
                await pool.query("INSERT INTO Rooms (id, display_name, pin, creator) VALUES ($1, $2, $3, $4)"
                    , [roomId, display_name, hashedPassword, userId]);
            }

            res.status(201).json({message: `Room ${roomId} created with display name ${display_name}.`});

        } catch (err) {
            console.error(err);
            res.status(403).json({error: "Invalid or expired token."});
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Internal server error."});
    }
});

app.post("/api/rooms/:roomId", async (req: Request, res: Response): Promise<void> => {
    const pin: string | null = req.body.pin;
    const auth: string| undefined = req.headers.authorization?.split(" ")[1];
    let room ;
    if (!auth){
        res.status(403).json({error: "Authorization missing."});
        return;
    }
    const { roomId } = req.params;

    if (!checkValidCharsForDB(roomId)) {
        res.status(403).json({ error: "Invalid chars." });
        return;
    }

    try {
        const result =
            await pool.query("Select id, pin, creator from Rooms WHERE id = $1", [roomId]);
        if (result.rows.length === 0){
            res.status(404).json({error: "Room not found."});
            return;
        }
        room = result.rows[0];
    } catch (err) {
        res.status(500).json({error: "Database error."})
        return;
    }

    //Checking auth.
    let userConfirm: {id: string};
    try {
        userConfirm = jwt.verify(auth, JWT_SECRET) as { id: string };
    } catch (err){
        console.error("Caught error with jwt verify.")
        res.status(500).json({error: "Error verifying"});
        return ;
    }
    if (!userConfirm){
        res.status(403).json({error: "Invalid jwt token."});
        return;
    }
    //Creating key.
    const roomToken = jwt.sign({roomId: roomId, userId: userConfirm.id}
        , ROOM_SECRET_KEY
        , {expiresIn: ROOM_SECRET_EXPIRY});
    //Checking if pin is needed.
    if (room.pin === null){
        console.log("Success.")
        res.status(200).json({
            message: "Joined room: " + roomId,
            roomToken: roomToken
        })
        return;
    }
    //Requiring pin.
    if (pin === null){
        res.status(403).json("This room is pin protected, provide a pin.");
        return;
    }
    //Checking with db if its the right key.
    const roomPin = await bcrypt.compare(pin, room.pin);
    if (!roomPin){
        res.status(403).json({error: "Invalid Password"});
        return;
    }
    //Success.
    res.status(200).json({
        message: "Joined room: " + roomId,
        roomToken: roomToken
    })
    return;
})


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
    const checkForDbManipulation = checkValidCharsForDB(roomId);
    if (!checkForDbManipulation){
        res.status(403).json({error: "Invalid characters in request."});
        return;
    }
    try {
        const result =
            await pool.query("SELECT id, display_name, creator FROM Rooms WHERE id = $1"
                , [roomId]);
        if (result.rows.length > 0) {
            res.status(200).json({ room: result.rows[0] });
        } else {
            res.status(404).json({ error: "Room not found." });
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Database error occurred." });
    }
})

app.delete("/api/rooms/:roomId", async (req: Request, res: Response) => {
    const { roomId } = req.params;
    const checkValidityOfChars = checkValidCharsForDB(roomId);
    if (!checkValidityOfChars){
        res.status(403).json({error: "Invalid characters in request."});
        return;
    }
    if (!req.headers.authorization){
        res.status(403).json({error: "Authorization missing."});
        return;
    }
    const auth = req.headers.authorization?.split(" ")[1];

    let user = null;
    try {
         user = jwt.verify(auth, JWT_SECRET) as { id: string };
    } catch (err:any){
        res.status(403).json({error: "User is not authorized."});
        return;
    }
    if (!user){
        res.status(500).json({error: "Error verifying"});
    }

    try {
        const results = await pool.query("SELECT * FROM Rooms WHERE id = $1 AND creator = $2"
            , [roomId, user.id]);
        if (results.rows.length > 0) {
            const deleteResults = await pool.query("Delete FROM Rooms WHERE id = $1 AND creator = $2"
                , [roomId, user.id]);
            res.status(200).json({message: `Successfully deleted room: ${roomId}`})
            return;
        }
        res.status(404).json({error: "Room not found."});
        return
    } catch (e: any){
        res.status(500).json({error: "Database error occurred."});
        return;
    }
})

app.get("/socket.io/", (req, res) => {
    res.send("WebSocket endpoint working!");
});


app.post("/api/messages", async (req: Request, res: Response): Promise<void> => {
    const message = req.body.message;

    if (!message){
        res.status(400).json({error: "Missing a message."});
        return;
    }

    if (!req.headers.authorization){
        res.status(403).json({error: "Authorization missing."});
        return;
    }

    const verify  =
        jwt.verify(req.headers.authorization, JWT_SECRET) as {userId: string, roomId: string};

    if (!verify){
        res.status(403).json({error: "Invalid verify token."});
        return;
    }

    const sender: string = verify.userId;
    const room: string = verify.roomId;

    const sendMessage =
        await  events.post("/default/" + room, {message: message, sender: sender});
    if (!sendMessage){
        res.status(500).json({error: "Could not post message to aws."});
        return;
    }
    res.status(200).json({message: "Message sent."});
})

app.post("/api/passwordReset", async (req: Request, res: Response): Promise<void> => {
    const MAILJET_API_KEY = process.env.MAILJET_API_KEY;
    const MAILJET_PRIVATE_KEY = process.env.MAILJET_PRIVATE_KEY;
    if (!MAILJET_API_KEY || !MAILJET_PRIVATE_KEY){
        res.status(500).json({error: "Internal Server Error."})
    }
    const userMail: string = JSON.parse(req.body).mail;
    if (!userMail){
        res.status(404).json({error: "Email is missing."})
    }

    // check db for existing email address
    try {
        const dbResult = await pool.query("Select email FROM Users where email = $1",
            [userMail]);
        if (dbResult.rows.length > 1){
            res.status(500).json({error: "Email has too many accounts associated."})
            return;
        }
    } catch (e: any) {
        res.status(200).json({message: `Email send to ${userMail}`});
    }

    const changedPassword: string = ""

    const mailjet = new Mailjet({
        apiKey: MAILJET_API_KEY,
        apiSecret: MAILJET_PRIVATE_KEY})
    const mailJetRequest = mailjet.post("send", {version: "v3.1"}).request({
        Messages: [
            {
                From: {
                    Email: "no-reply@HSZG.Chat-App.de",
                    Name: "HSZG Chat App"
                },
                To: [
                    {
                        Email: userMail,
                        Name: "Chat App User"
                    }
                ],
                Subject: "Password Reset of your HSZG Chat App Account",
                TextPart: "Mail from Backend",
                HTMLPart:
                    "<h3>New Password for your account</h3>" +
                    "<p>Your new Password: " +
                    changedPassword
                    + "</p>"
            }
        ]
    })
    mailJetRequest
        .then(result => {
            console.log("Successfully send mail.");
            res.status(200).json({message: `Email send to ${userMail}`});
            return;
        })
        .catch(err => {
            console.log("Error sending mail.");
            res.status(500).json({error: "Internal Server error"});
            return;
        });

    res.status(500).json({error: "Internal Server error"});
})


// server


const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: ["https://chat-app-iib23-frontend-47fb2c785a51.herokuapp.com",
            "https://chat-app-angular-dbba048e2d37.herokuapp.com"],
        methods: ["GET", "POST", "PUT", "DELETE"],
    }
});

io.on("connection", (socket) => {
    console.log("Client connected: " + socket.id);

    socket.on("joinRoom", ({ roomId }) => {
        socket.join(roomId);
        console.log(`User joined room: ${roomId}`);
    });

    socket.on("message", ({ token, message, user, roomId }) => {
        console.log(`Message received from ${user}: ${message}`);

        // Broadcast the message to everyone in the same room
        io.to(roomId).emit("message", { user, message });
    });

    socket.on("disconnect", () => {
        console.log("Client disconnected: " + socket.id);
    });
});



app.listen(process.env.PORT, () => {
    console.log("Server listening")
})
