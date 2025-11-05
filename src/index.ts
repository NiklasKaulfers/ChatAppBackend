import pg from "pg";
import express, {NextFunction, Request, Response} from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import { v4 as uuidV4 } from "uuid";
import {checkValidCharsForDB} from "./check-valid-chars-for-db";
import {Server, Socket} from "socket.io";
import {createServer} from "node:http";
import Mailjet from "node-mailjet";

const MAILJET_API_KEY = process.env.MAILJET_API_KEY;
const MAILJET_PRIVATE_KEY = process.env.MAILJET_PRIVATE_KEY;
const CHAT_EMAIL = process.env.EMAIL;
const ROOM_SECRET_KEY = process.env.ROOM_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const HANDSHAKE_KEY = process.env.HANDSHAKE_KEY;
if (!JWT_SECRET
    || !process.env.DATABASE_URL
    || !ROOM_SECRET_KEY
    || !HANDSHAKE_KEY
    || !MAILJET_API_KEY
    || !MAILJET_PRIVATE_KEY
    || !CHAT_EMAIL) {
    console.error("At least 1 missing secret")
    throw new Error("Secrets are missing.");
}


const PORT = process.env.PORT || 3000;
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
    origin: ["https://chat-app-angular-flax.vercel.app"],
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Authorization", "Content-Type", "Access-Control-Allow-Origin"],
    credentials: true,
    optionsSuccessStatus: 204,
}));
const httpServer = createServer(app);
const io = new Server(httpServer, {
    cors: {
        origin: ["https://chat-app-angular-flax.vercel.app"],
        methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allowedHeaders: ["Authorization", "Content-Type", "Access-Control-Allow-Origin"],
    }
});

app.options("*", cors());


httpServer.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} with socket.io support`);
});


const generateRandomId = (): string => uuidV4();

const generateAccessToken = (userId: string): string => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRY });
};

const generateRefreshToken = (userId: string): string => {
    return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: REFRESH_TOKEN_EXPIRY });
};


const verifyPassword = async (inputPassword: string, storedPassword: string): Promise<boolean> => {
    // Trim the input password to remove any accidental whitespace
    const cleanPassword = inputPassword.trim();

    try {
        // Try the async compare first
        return await bcrypt.compare(cleanPassword, storedPassword);
    } catch (err) {
        console.error("Async bcrypt compare failed, trying sync compare:", err);

        // Fall back to sync compare if the async one fails
        try {
            return bcrypt.compareSync(cleanPassword, storedPassword);
        } catch (syncErr) {
            console.error("Both async and sync bcrypt compare failed:", syncErr);
            return false;
        }
    }
};

/*


            API Endpoints


 */


app.options("*", (req, res) => {
    console.log(`Received OPTIONS request for ${req.path}`);
    res.status(204).send();
});

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

app.get("/api/users/:userId", async (req: Request, res: Response) => {
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    if (!auth){
        res.status(403).json({error: "Authorization missing."})
        return ;
    }
    try {
        console.log("Attempting to verify token")
        const user = jwt.verify(auth, JWT_SECRET) as {id: string};
        if (!user){
            res.status(403).json({error: "Invalid token."})
            return ;
        }
        try {
            const dbResult = await pool.query("SELECT id, email FROM users WHERE id = $1", [user.id]);

            if (dbResult.rows.length !== 1){
                res.status(404).json({error: "User not found."});
                return;
            }
            res.status(200).json({
                id: dbResult.rows[0].id,
                email: dbResult.rows[0].email
            });
        } catch (e){
            console.log("API Call users/:userId caused an error in the database.", e)
            res.status(500).json({error: "Internal Server error."});
            return;
        }
    } catch (e: any) {
        console.log("Error verifying token:", e)
        if (e.name === 'TokenExpiredError') {
            console.log("Token expired")
            res.status(401).json({error: "Token expired."});
        } else if (e.name === 'JsonWebTokenError') {
            console.log("Token invalid");
            res.status(401).json({error: "Invalid token."});
        } else {
            res.status(500).json({error: "Internal Server error."});
        }
        return;
    }
})


//login
app.post("/api/login", async (req: Request, res: Response): Promise<void> => {
    console.log("Login attempt initiated");
    const username: string | undefined = req.body.username;
    const password: string | undefined = req.body.password;

    if (!username || !password) {
        console.log("Login failed: Missing username or password");
        res.status(400).json({ error: "Username and password are required." });
        return;
    }

    try {
        console.log(`Finding user with username: ${username}`);
        // Ensure we're getting the exact field from database
        const result = await pool.query("SELECT id, pin FROM users WHERE id = $1", [username]);
        if (result.rows.length === 0) {
            console.log(`Login failed: No user found with username ${username}`);
            res.status(404).json({ error: "No user found." });
            return;
        }

        const user = result.rows[0];
        const storedHash = user.pin;

        console.log(`User found, attempting to verify password`);
        console.log(`Password length: ${password.length}, Hash length: ${storedHash.length}`);

        // Log password characters to check for invisible characters or encoding issues
        const passwordChars = Array.from(password).map(c => c.charCodeAt(0));
        console.log(`Password character codes: ${passwordChars.join(', ')}`);

        // Try multiple verification approaches
        let passwordMatch = false;

        // Approach 1: Standard bcrypt compare
        try {
            passwordMatch = await bcrypt.compare(password, storedHash);
            console.log(`Standard bcrypt compare result: ${passwordMatch}`);
        } catch (compareErr) {
            console.error("Error during bcrypt compare:", compareErr);
        }

        // Approach 2: If standard compare fails, try with trimmed password
        if (!passwordMatch && password !== password.trim()) {
            try {
                const trimmedResult = await bcrypt.compare(password.trim(), storedHash);
                console.log(`Trimmed password compare result: ${trimmedResult}`);
                passwordMatch = trimmedResult;
            } catch (trimErr) {
                console.error("Error during trimmed password compare:", trimErr);
            }
        }

        // Approach 3: Try with sync compare as a last resort
        if (!passwordMatch) {
            try {
                const syncResult = bcrypt.compareSync(password, storedHash);
                console.log(`Sync compare result: ${syncResult}`);
                passwordMatch = syncResult;
            } catch (syncErr) {
                console.error("Error during sync compare:", syncErr);
            }
        }

        if (!passwordMatch) {
            console.log(`Login failed: Invalid password for user ${username}`);
            res.status(403).json({ error: "Invalid password." });
            return;
        }

        console.log(`Login successful for user ${username}`);
        const accessToken: string = generateAccessToken(user.id);
        const refreshToken: string = generateRefreshToken(user.id);
        refreshTokens[user.id] = refreshToken;
        res.status(200).json({
            message: `Logged in as ${username}`,
            accessToken: accessToken,
            refreshToken: refreshToken
        });
    } catch (err) {
        console.error(`Login error for user ${username}:`, err);
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
    const roomToken: string | undefined = req.body.roomtoken;
    const room: string | undefined = req.body.room;
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
                await pool.query("INSERT INTO rooms (id, display_name, creator) VALUES ($1, $2, $3)"
                    , [roomId, display_name, userId]);
            } else {
                const hashedPassword = await bcrypt.hash(pin, 10);
                await pool.query("INSERT INTO rooms (id, display_name, pin, creator) VALUES ($1, $2, $3, $4)"
                    , [roomId, display_name, hashedPassword, userId]);
            }

            res.status(201).json({message: `Room ${roomId} created with display name ${display_name}.`});
            return;
        } catch (err) {
            console.error(err);
            res.status(403).json({error: "Invalid or expired token."});
            return ;
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Internal server error."});
        return;
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
    //Checking auth.
    let userConfirm: {id: string};
    try {
        userConfirm = jwt.verify(auth, JWT_SECRET) as { id: string };
    } catch (err){
        console.error("Caught error with jwt verify.")
        res.status(500).json({error: "Error verifying"});
        return;
    }
    if (!userConfirm){
        res.status(403).json({error: "Invalid jwt token."});
        return;
    }
    const { roomId } = req.params;

    if (!checkValidCharsForDB(roomId)) {
        res.status(403).json({ error: "Invalid chars." });
        return;
    }

    try {
        const result =
            await pool.query("Select id, pin, creator from rooms WHERE id = $1", [roomId]);
        if (result.rows.length === 0){
            res.status(404).json({error: "Room not found."});
            return;
        }
        room = result.rows[0];
    } catch (err) {
        res.status(500).json({error: "Database error."})
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
                "SELECT id, display_name, creator,(pin IS NOT NULL) AS has_password FROM rooms"
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

app.get("/api/rooms/ownedByUser", async (req: Request, res: Response): Promise<void> => {
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    if (!auth){
        res.status(403).json({error: "Authorization missing."})
        return ;
    }
    const verify = verifyToken(auth);
    if (!verify){
        res.status(403).json({error: "Illegal login"});
        return;
    }
    const user = jwt.verify(auth, JWT_SECRET) as {id: string};
    if (!user){
        res.status(403).json({error: "Authorization missing."})
        return ;
    }

    try {
        const rooms = await pool.query(
            "Select id,display_name, creator, case when pin is null then 'False' else 'True' end as has_password from rooms "
            + "where creator = $1", [user.id]
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
})

app.get("/api/rooms/:roomId", async (req: Request, res: Response): Promise<void> => {
    const { roomId } = req.params;
    const checkForDbManipulation = checkValidCharsForDB(roomId);
    if (!checkForDbManipulation){
        res.status(403).json({error: "Invalid characters in request."});
        return;
    }
    try {
        const result =
            await pool.query("SELECT id, display_name, creator FROM rooms WHERE id = $1"
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

/**
 * req.params: the room to delete
 * req.headers.authorization: the user verification of the owner of that room
 */
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
    const verify = verifyToken(auth);
    if (!verify){
        res.status(403).json({error: "Illegal login"});
        return;
    }
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
        const results = await pool.query("SELECT * FROM rooms WHERE id = $1 AND creator = $2"
            , [roomId, user.id]);
        if (results.rows.length > 0) {
            const deleteResults = await pool.query("Delete FROM rooms WHERE id = $1 AND creator = $2"
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
    // todo work in process
    const sendMessage = ""
    if (!sendMessage){
        res.status(500).json({error: "Could not post message to aws."});
        return;
    }
    res.status(200).json({message: "Message sent."});
})

app.post("/api/passwordManagement/changePassword", async (req: Request, res: Response): Promise<void> => {
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    if (!auth){
        res.status(403).json({error: "Authorization is missing."})
        return ;
    }
    const verify = verifyToken(auth);
    if (!verify){
        res.status(403).json({error: "Illegal login"});
        return;
    }
    const newPassword: string | undefined = req.body.newPassword;
    if (!newPassword){
        res.status(400).json({error: "Credentials for update are missing."})
        return ;
    }
    const user = jwt.verify(auth as string, JWT_SECRET) as {id:string};
    if (!user){
        res.status(403).json({error: "Invalid verify token."});
        return;
    }

    if (!checkValidCharsForDB(newPassword)){
        res.status(400).json({error: "Invalid characters"});
        return;
    }

    const state = await changePasswordOfUser(user.id, newPassword);
    if (state.json.error){
        res.status(state.state).json(state.json);
        return;
    }
    if (state.json.message){
        res.status(state.state).json(state.json);
        return;
    }
    res.status(500).json({error: "Internal Server Error."})
    return

})

app.post("/api/passwordManagement/passwordReset", async (req: Request, res: Response): Promise<void> => {
    const userMail: string | undefined = req.body.userMail;
    console.log(`Password reset requested for email: ${userMail}`);

    if (!userMail) {
        console.log("Password reset failed: Email is missing");
        res.status(400).json({ error: "Email is missing." });
        return;
    }

    if (!checkValidCharsForDB(userMail)) {
        console.log(`Password reset failed: Invalid characters in email: ${userMail}`);
        res.status(400).json({ error: "Invalid characters in email." });
        return;
    }

    try {
        console.log(`Looking up user with email: ${userMail}`);
        const dbResult = await pool.query("SELECT email, id FROM users WHERE email = $1", [userMail]);

        if (dbResult.rows.length !== 1) {
            console.log(`Password reset failed: Email not found or has multiple accounts: ${userMail}`);
            res.status(404).json({ error: "Email not found or has multiple accounts." });
            return;
        }

        const userId = dbResult.rows[0].id;
        console.log(`User found with ID: ${userId}`);

        // Generate password with alphanumeric characters only
        const changedPassword: string = generatePasswordArray(10); // Increased to 10 characters for better security
        console.log(`Generated new password for user ${userId}`);

        const state = await changePasswordOfUser(userId, changedPassword);

        if (state.json.error) {
            console.log(`Password reset failed: ${state.json.error}`);
            res.status(state.state).json(state.json);
            return;
        }

        // Create a more user-friendly email with clear instructions
        const emailBody = `
            <html>
                <body style="font-family: Arial, sans-serif; line-height: 1.6;">
                    <h2>Password Reset for HSZG Chat App</h2>
                    <p>A password reset was requested for your account.</p>
                    <p>Your new password is: <strong>${changedPassword}</strong></p>
                    <p>Please log in with this password and change it immediately for security reasons.</p>
                    <p>If you did not request this password reset, please contact support.</p>
                </body>
            </html>
        `;

        console.log(`Sending password reset email to: ${userMail}`);
        const mailjet = new Mailjet({ apiKey: MAILJET_API_KEY, apiSecret: MAILJET_PRIVATE_KEY });
        const mailJetRequest = await mailjet.post("send", { version: "v3.1" }).request({
            Messages: [
                {
                    From: { Email: CHAT_EMAIL, Name: "HSZG Chat App" },
                    To: [{ Email: userMail }],
                    Subject: "Password Reset for your HSZG Chat App Account",
                    TextPart: `Your new password is: ${changedPassword}`,
                    HTMLPart: emailBody
                }
            ]
        });

        if (mailJetRequest.response.status === 200) {
            console.log(`Password reset email sent successfully to: ${userMail}`);
            res.status(200).json({ message: `Email sent to ${userMail}` });
            return;
        } else {
            console.error("MailJet error:", mailJetRequest.response);
            res.status(500).json({ error: "Failed to send email." });
            return;
        }

    } catch (err) {
        console.error("Password reset - Database or processing error:", err);
        res.status(500).json({ error: "Internal Server error" });
        return;
    }
});

interface ResponseStateAndJson{
    state: number,
    json: {
        message?: string,
        error?: string
    }
}



function generatePasswordArray(length: number) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const password = Array.from({ length }, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
    console.log(`Generated password length: ${password.length}`);
    return password;
}
const verifyToken = (token: string) => {
    try {
        return jwt.verify(token, JWT_SECRET);
    } catch (error: any) {
        console.error("JWT Verification Failed:", error.message);
        return null;
    }
};
async function changePasswordOfUser(user: string, newPassword: string): Promise<ResponseStateAndJson> {
    try {
        console.log(`Changing password for user: ${user}`);
        console.log(`New password length: ${newPassword.length}`);

        // Ensure the password is clean of any whitespace
        const cleanPassword = newPassword.trim();

        // Use a consistent salt round value
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(cleanPassword, saltRounds);
        console.log(`Generated hash length: ${hashedPassword.length}`);

        // Verify the hash immediately after generation
        const verificationResult = await bcrypt.compare(cleanPassword, hashedPassword);
        console.log(`Immediate verification after hash generation: ${verificationResult}`);

        if (!verificationResult) {
            console.error("Generated hash failed immediate verification!");
            return {
                state: 500,
                json: { error: "Password hashing verification failed" }
            };
        }

        const dbResponse = await pool.query("UPDATE users SET pin = $1 WHERE id = $2 RETURNING *", [
            hashedPassword, user
        ]);

        if (dbResponse.rowCount === 0) {
            console.log(`Password change failed: User ${user} not found`);
            return {
                state: 404,
                json: { error: "User not found" }
            };
        }

        console.log(`Password successfully updated for user: ${user}`);
        return {
            state: 200,
            json: { message: "Password successfully updated" }
        };
    } catch (e) {
        console.error(`Error updating password for user ${user}:`, e);
        return {
            state: 500,
            json: { error: "Internal Server Error" }
        };
    }
}
// server


// having issues rn
// todo: fix of websocket

interface SocketUser {
    id: string;
    roomId: string;
}

interface AuthenticatedSocket extends Socket {
    user: SocketUser;
}

interface RoomUsersMap {
    [roomId: string]: Set<string>;
}



const roomUsers: RoomUsersMap = {};

io.use((socket: Socket, next) => {
const token = socket.handshake.auth.token;
if (!token) {
    return next(new Error("Authentication error: Token missing"));
}

try {
    // Verify the token
    const decoded = jwt.verify(token, ROOM_SECRET_KEY) as { userId: string, roomId: string };
    (socket as AuthenticatedSocket).user = {
        id: decoded.userId,
        roomId: decoded.roomId
    };
    next();
} catch (error) {
    console.error("Socket authentication error:", error);
    next(new Error("Authentication error: Invalid token"));
}
});

io.on("connection", (socket: Socket) => {
    const authenticatedSocket = socket as AuthenticatedSocket;
    const userId = authenticatedSocket.user.id;
    const roomId = authenticatedSocket.user.roomId;

    console.log(`Client connected: ${socket.id}, User: ${userId}`);

    socket.join(roomId);

    if (!roomUsers[roomId]) {
        roomUsers[roomId] = new Set<string>();
    }
    roomUsers[roomId].add(userId);

    io.to(roomId).emit("userJoined", {
        user: userId,
        activeUsers: Array.from(roomUsers[roomId])
    });

    socket.on("message", async (data: { message: string }) => {
        const { message } = data;

        if (!message || message.trim() === "") {
            socket.emit("error", { message: "Message cannot be empty" });
            return;
        }

        try {
            io.to(roomId).emit("message", {
                id: generateRandomId(),
                user: userId,
                message,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            console.error("Error processing message:", error);
            socket.emit("error", { message: "Failed to process message" });
        }
    });

    socket.on("typing", (isTyping: boolean) => {
        socket.to(roomId).emit("userTyping", {
            user: userId,
            isTyping
        });
    });

    socket.on("disconnect", () => {
        console.log(`Client disconnected: ${socket.id}, User: ${userId}`);

        if (roomUsers[roomId]) {
            roomUsers[roomId].delete(userId);

            io.to(roomId).emit("userLeft", {
                user: userId,
                activeUsers: Array.from(roomUsers[roomId])
            });

            if (roomUsers[roomId].size === 0) {
                delete roomUsers[roomId];
            }
        }
    });
});

app.use((req: Request, res: Response, next: NextFunction) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    const originalSend = res.send;
    res.send = function(body) {
        console.log(`${new Date().toISOString()} - Response ${res.statusCode} for ${req.method} ${req.url}`);
        return originalSend.call(this, body);
    };
    next();
});

app.use((err: Error, req: Request, res: Response, next: Function) => {
    console.error(`Server error: ${err.message}`);
    if (!res.headersSent) {
        res.status(500).json({ error: "Internal server error" });
    }
});
