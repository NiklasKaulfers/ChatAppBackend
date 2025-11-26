import express, {NextFunction, Request, Response} from "express";
import bcrypt from "bcryptjs";
import cors from "cors";
import jwt from "jsonwebtoken";
import {v4 as uuidV4} from "uuid";
import {checkValidCharsForDB} from "./helpers/check-valid-chars-for-db";
import {Server, Socket} from "socket.io";
import {createServer} from "node:http";
import Mailjet from "node-mailjet";
import {createClient} from "@supabase/supabase-js"

import {generateAccessToken, generateRefreshToken} from "./helpers/jwt-helper";
import {handleStatusRequest} from "./handlers/status";

const MAILJET_API_KEY = process.env.MAILJET_API_KEY;
const MAILJET_PRIVATE_KEY = process.env.MAILJET_PRIVATE_KEY;
const CHAT_EMAIL = process.env.EMAIL;
const ROOM_SECRET_KEY = process.env.ROOM_SECRET_KEY;
const JWT_SECRET = process.env.JWT_SECRET;
const HANDSHAKE_KEY = process.env.HANDSHAKE_KEY;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
if (!JWT_SECRET
    || !ROOM_SECRET_KEY
    || !HANDSHAKE_KEY
    || !MAILJET_API_KEY
    || !MAILJET_PRIVATE_KEY
    || !CHAT_EMAIL) {
    console.error("At least 1 missing secret")
    throw new Error("Secrets are missing.");
}

const SUPABASE_USERS_UNIQUENESS_ERROR = "duplicate key value violates unique constraint \"users_email_key\""

if (!SUPABASE_KEY || !SUPABASE_URL) {
    console.error("Supabase info missing.")
    throw new Error("Supabase info missing.");
}


const PORT = process.env.PORT || 3000;

const ROOM_SECRET_EXPIRY = "2h";
// todo: this bad bad, add to db eventually
const refreshTokens: Record<string, string> = {};


const supabase = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!)
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

app.options("/*", cors());


httpServer.listen(PORT, () => {
    console.log(`Server listening on port ${PORT} with socket.io support`);
});



app.options("/*", (req, res) => {
    console.log(`Received OPTIONS request for ${req.path}`);
    res.status(204).send();
});

app.get("/api/status", async (req: Request, res: Response): Promise<void> => {
    res = await handleStatusRequest(req, res);
});


//users


app.post("/api/users", async (req: Request, res: Response) => {
    const {user, email, password} = req.body;

    if (!user || !email || !password) {
        res.status(400).json({error: "User, email, and password are required."});
        return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const {error, data} = await supabase.from("users").insert([{id: user, email: email, pin: hashedPassword}]).select();

    if (error) {
        console.error(error);
        res.status(500).json({error: "Database error occurred."});
        return;
    }
    if (!data?.[0]?.id){
        res.status(500).json({error: "User creation failed."});
        return;
    }
    res.status(201).json({message: `User ${user} has been created.`});
});

app.get("/api/users/:userId", async (req: Request, res: Response) => {
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    if (!auth) {
        res.status(403).json({error: "Authorization missing."})
        return;
    }
    try {
        console.log("Attempting to verify token")
        const user = jwt.verify(auth, JWT_SECRET) as { id: string };
        if (!user) {
            res.status(403).json({error: "Invalid token."})
            return;
        }
        try {
            // { changed code }
            const {data, error} = await supabase
                .from("users")
                .select("id, email")
                .eq("id", user.id)
                .limit(1);

            if (error) {
                console.error("Supabase error:", error);
                res.status(500).json({error: "Internal Server error."});
                return;
            }

            if (!data || data.length === 0) {
                res.status(404).json({error: "User not found."});
                return;
            }

            res.status(200).json({
                id: data[0].id,
                email: data[0].email
            });
        } catch (e) {
            console.log("API Call users/:userId caused an error.", e)
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
        res.status(400).json({error: "Username and password are required."});
        return;
    }

    try {
        console.log(`Finding user with username: ${username}`);
        // { changed code }
        const {data, error} = await supabase
            .from("users")
            .select("id, pin")
            .eq("id", username)
            .limit(1);

        if (error) {
            if (error.message === SUPABASE_USERS_UNIQUENESS_ERROR){
                res.status(404).json({error: "Email is already registered."});
                return ;
            } else {
                console.error("Supabase error:", error);
                res.status(500).json({error: "Database error occurred."});
                return;
            }
        }

        if (!data || data.length === 0) {
            console.log(`Login failed: No user found with username ${username}`);
            res.status(404).json({error: "No user found."});
            return;
        }

        const user = data[0];
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
            res.status(403).json({error: "Invalid password."});
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
        res.status(500).json({error: "Database error occurred."});
    }
});

// token

app.post("/api/tokenRefresh", (req: Request, res: Response): void => {
    const {refreshToken} = req.body;

    if (!refreshToken) {
        res.status(400).json({error: "Refresh token is required."});
        return;
    }

    try {
        const decoded = jwt.verify(refreshToken, JWT_SECRET) as { id: string };
        const userId = decoded.id;

        if (refreshTokens[userId] !== refreshToken) {
            res.status(403).json({error: "Invalid or expired refresh token."});
            return;
        }

        const newAccessToken = generateAccessToken(userId);
        res.status(200).json({message: "Token refreshed successfully", accessToken: newAccessToken});
    } catch (err) {
        console.error(err);
        res.status(403).json({error: "Invalid or expired refresh token."});
    }
});


// verification to be used by lambda
// todo: should prop be options or smth
app.post("/api/rooms/verifyUser", async (req: Request, res: Response): Promise<void> => {
    const roomToken: string | undefined = req.body.roomtoken;
    const room: string | undefined = req.body.room;
    if (!roomToken) {
        res.status(400).json({error: "Room token is required."});
        return;
    }
    const auth = jwt.verify(roomToken, JWT_SECRET) as { roomId: string, userId: string };
    if (auth && room === auth.roomId) {
        res.status(200).json({message: "Successfully verified user."});
        return;
    }
    if (!auth) {
        res.status(403).json({error: "Invalid or expired token."});
    }
    if (room !== auth.roomId) {
        res.status(403).json({error: "Verification not for this room."});
    }
})

// rooms


app.post("/api/rooms", async (req: Request, res: Response): Promise<void> => {
    const {pin, display_name} = req.body;
    const roomId = uuidV4();


    try {
        const token: string | undefined = req.headers.authorization?.split(" ")[1];

        if (!token) {
            res.status(400).json({error: "Authorization token is required."})
            return;
        }

        try {
            const decoded = jwt.verify(token, JWT_SECRET) as { id: string };
            let userId = decoded.id;


            // { changed code: check user exists via supabase }
            const {data: userData, error: userError} = await supabase
                .from("users")
                .select("id")
                .eq("id", userId)
                .limit(1);

            if (userError) {
                console.error("Supabase error:", userError);
                res.status(500).json({error: "Internal server error."});
                return;
            }

            if (!userData || userData.length === 0) {
                res.status(404).json({error: "User not found."});
                return;
            } else {
                userId = userData[0].id;
            }

            // ...existing code for input validation...

            if (!pin) {
                await supabase.from("rooms").insert([{id: roomId, display_name: display_name, creator: userId}]);
            } else {
                const hashedPassword = await bcrypt.hash(pin, 10);
                await supabase.from("rooms").insert([{
                    id: roomId,
                    display_name: display_name,
                    pin: hashedPassword,
                    creator: userId
                }]);
            }

            res.status(201).json({message: `Room ${roomId} created with display name ${display_name}.`});
            return;
        } catch (err) {
            console.error(err);
            res.status(403).json({error: "Invalid or expired token."});
            return;
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Internal server error."});
        return;
    }
});

app.post("/api/rooms/:roomId", async (req: Request, res: Response): Promise<void> => {
    const pin: string | null = req.body.pin;
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    let room;
    if (!auth) {
        res.status(403).json({error: "Authorization missing."});
        return;
    }
    //Checking auth.
    let userConfirm: { id: string };
    try {
        userConfirm = jwt.verify(auth, JWT_SECRET) as { id: string };
    } catch (err) {
        console.error("Caught error with jwt verify.")
        res.status(500).json({error: "Error verifying"});
        return;
    }
    if (!userConfirm) {
        res.status(403).json({error: "Invalid jwt token."});
        return;
    }
    const {roomId} = req.params;

    if (!checkValidCharsForDB(roomId)) {
        res.status(403).json({error: "Invalid chars."});
        return;
    }

    try {
        // { changed code }
        const {data: roomData, error: roomError} = await supabase
            .from("rooms")
            .select("id, pin, creator")
            .eq("id", roomId)
            .limit(1);

        if (roomError) {
            console.error("Supabase error:", roomError);
            res.status(500).json({error: "Database error."})
            return;
        }

        if (!roomData || roomData.length === 0) {
            res.status(404).json({error: "Room not found."});
            return;
        }
        room = roomData[0];
    } catch (err) {
        res.status(500).json({error: "Database error."})
        return;
    }


    //Creating key.
    const roomToken = jwt.sign({roomId: roomId, userId: userConfirm.id}
        , ROOM_SECRET_KEY
        , {expiresIn: ROOM_SECRET_EXPIRY});
    //Checking if pin is needed.
    if (room.pin === null) {
        console.log("Success.")
        res.status(200).json({
            message: "Joined room: " + roomId,
            roomToken: roomToken
        })
        return;
    }
    //Requiring pin.
    if (pin === null) {
        res.status(403).json("This room is pin protected, provide a pin.");
        return;
    }
    //Checking with db if its the right key.
    const roomPin = await bcrypt.compare(pin, room.pin);
    if (!roomPin) {
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
        // { changed code: fetch rooms and compute has_password client-side }
        const {data, error} = await supabase
            .from("rooms")
            .select("id, display_name, creator, pin");

        if (error) {
            console.error("Supabase error:", error);
            res.status(500).json({error: "Database error occurred."});
            return;
        }

        if (!data || data.length === 0) {
            res.status(200).json({message: "No rooms found.", ids: []});
            return;
        }

        const rooms = data.map((r: any) => ({
            id: r.id,
            display_name: r.display_name,
            creator: r.creator,
            has_password: r.pin != null
        }));

        res.status(200).json({rooms});
    } catch (error) {
        console.error(error);
        res.status(500).json({error: "Database error occurred."});
    }
});

// GET /api/rooms/ownedByUser
app.get("/api/rooms/ownedByUser", async (req: Request, res: Response): Promise<void> => {
    const auth: string | undefined = req.headers.authorization?.split(" ")[1];
    if (!auth) {
        res.status(403).json({error: "Authorization missing."})
        return;
    }
    const verify = verifyToken(auth);
    if (!verify) {
        res.status(403).json({error: "Illegal login"});
        return;
    }
    const user = jwt.verify(auth, JWT_SECRET) as { id: string };
    if (!user) {
        res.status(403).json({error: "Authorization missing."})
        return;
    }

    try {
        // { changed code: select rooms by creator and compute has_password }
        const {data, error} = await supabase
            .from("rooms")
            .select("id, display_name, creator, pin")
            .eq("creator", user.id);

        if (error) {
            console.error("Supabase error:", error);
            res.status(500).json({error: "Database error occurred."});
            return;
        }

        if (!data || data.length === 0) {
            res.status(200).json({message: "No rooms found.", ids: []});
            return;
        }

        const rooms = data.map((r: any) => ({
            id: r.id,
            display_name: r.display_name,
            creator: r.creator,
            has_password: r.pin != null
        }));

        res.status(200).json({rooms});
    } catch (error) {
        console.error(error);
        res.status(500).json({error: "Database error occurred."});
    }
})

// GET /api/rooms/:roomId (room details)
app.get("/api/rooms/:roomId", async (req: Request, res: Response): Promise<void> => {
    const {roomId} = req.params;
    const checkForDbManipulation = checkValidCharsForDB(roomId);
    if (!checkForDbManipulation) {
        res.status(403).json({error: "Invalid characters in request."});
        return;
    }
    try {
        // { changed code }
        const {data, error} = await supabase
            .from("rooms")
            .select("id, display_name, creator")
            .eq("id", roomId)
            .limit(1);

        if (error) {
            console.error("Supabase error:", error);
            res.status(500).json({error: "Database error occurred."});
            return;
        }

        if (data && data.length > 0) {
            res.status(200).json({room: data[0]});
        } else {
            res.status(404).json({error: "Room not found."});
        }
    } catch (err) {
        console.error(err);
        res.status(500).json({error: "Database error occurred."});
    }
})

// DELETE /api/rooms/:roomId
app.delete("/api/rooms/:roomId", async (req: Request, res: Response) => {
    const {roomId} = req.params;
    const checkValidityOfChars = checkValidCharsForDB(roomId);
    if (!checkValidityOfChars) {
        res.status(403).json({error: "Invalid characters in request."});
        return;
    }
    if (!req.headers.authorization) {
        res.status(403).json({error: "Authorization missing."});
        return;
    }
    const auth = req.headers.authorization?.split(" ")[1];

    let user = null;
    const verify = verifyToken(auth);
    if (!verify) {
        res.status(403).json({error: "Illegal login"});
        return;
    }
    try {
        user = jwt.verify(auth, JWT_SECRET) as { id: string };
    } catch (err: any) {
        res.status(403).json({error: "User is not authorized."});
        return;
    }
    if (!user) {
        res.status(500).json({error: "Error verifying"});
    }

    try {
        // { changed code: check ownership then delete }
        const {data: existsData, error: existsError} = await supabase
            .from("rooms")
            .select("id")
            .match({id: roomId, creator: user.id})
            .limit(1);

        if (existsError) {
            console.error("Supabase error:", existsError);
            res.status(500).json({error: "Database error occurred."});
            return;
        }

        if (existsData && existsData.length > 0) {
            const {data: delData, error: delError} = await supabase
                .from("rooms")
                .delete()
                .match({id: roomId, creator: user.id});

            if (delError) {
                console.error("Supabase delete error:", delError);
                res.status(500).json({error: "Database error occurred."});
                return;
            }

            res.status(200).json({message: `Successfully deleted room: ${roomId}`})
            return;
        }
        res.status(404).json({error: "Room not found."});
        return
    } catch (e: any) {
        res.status(500).json({error: "Database error occurred."});
        return;
    }
})

// POST /api/passwordManagement/passwordReset
app.post("/api/passwordManagement/passwordReset", async (req: Request, res: Response): Promise<void> => {
    const userMail: string | undefined = req.body.userMail;
    console.log(`Password reset requested for email: ${userMail}`);

    if (!userMail) {
        console.log("Password reset failed: Email is missing");
        res.status(400).json({error: "Email is missing."});
        return;
    }

    if (!checkValidCharsForDB(userMail)) {
        console.log(`Password reset failed: Invalid characters in email: ${userMail}`);
        res.status(400).json({error: "Invalid characters in email."});
        return;
    }

    try {
        console.log(`Looking up user with email: ${userMail}`);
        // { changed code }
        const {data, error} = await supabase
            .from("users")
            .select("email, id")
            .eq("email", userMail)
            .limit(1);

        if (error) {
            console.error("Supabase error:", error);
            res.status(500).json({error: "Internal Server error"});
            return;
        }

        if (!data || data.length !== 1) {
            console.log(`Password reset failed: Email not found or multiple accounts: ${userMail}`);
            res.status(404).json({error: "Email not found or has multiple accounts."});
            return;
        }

        const userId = data[0].id;
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
        const mailjet = new Mailjet({apiKey: MAILJET_API_KEY, apiSecret: MAILJET_PRIVATE_KEY});
        const mailJetRequest = await mailjet.post("send", {version: "v3.1"}).request({
            Messages: [
                {
                    From: {Email: CHAT_EMAIL, Name: "HSZG Chat App"},
                    To: [{Email: userMail}],
                    Subject: "Password Reset for your HSZG Chat App Account",
                    TextPart: `Your new password is: ${changedPassword}`,
                    HTMLPart: emailBody
                }
            ]
        });

        if (mailJetRequest.response.status === 200) {
            console.log(`Password reset email sent successfully to: ${userMail}`);
            res.status(200).json({message: `Email sent to ${userMail}`});
            return;
        } else {
            console.error("MailJet error:", mailJetRequest.response);
            res.status(500).json({error: "Failed to send email."});
            return;
        }

    } catch (err) {
        console.error("Password reset - Database or processing error:", err);
        res.status(500).json({error: "Internal Server error"});
        return;
    }
});

interface ResponseStateAndJson {
    state: number,
    json: {
        message?: string,
        error?: string
    }
}


function generatePasswordArray(length: number) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const password = Array.from({length}, () => characters.charAt(Math.floor(Math.random() * characters.length))).join('');
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
                json: {error: "Password hashing verification failed"}
            };
        }

        const dbResponse = await supabase
            .from("users")
            .update({pin: hashedPassword})
            .eq("id", user)
            .select("*");

        if (!dbResponse || dbResponse.error) {
            console.error("Supabase update error:", dbResponse.error);
            return {
                state: 500,
                json: {error: "Internal Server Error"}
            };
        }

        const updated = dbResponse.data;
        if (!updated || updated.length === 0) {
            console.log(`Password change failed: User ${user} not found`);
            return {
                state: 404,
                json: {error: "User not found"}
            };
        }

        console.log(`Password successfully updated for user: ${user}`);
        return {
            state: 200,
            json: {message: "Password successfully updated"}
        };
    } catch (e) {
        console.error(`Error updating password for user ${user}:`, e);
        return {
            state: 500,
            json: {error: "Internal Server Error"}
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
        const {message} = data;

        if (!message || message.trim() === "") {
            socket.emit("error", {message: "Message cannot be empty"});
            return;
        }

        try {
            io.to(roomId).emit("message", {
                id: uuidV4(),
                user: userId,
                message,
                timestamp: new Date().toISOString()
            });

        } catch (error) {
            console.error("Error processing message:", error);
            socket.emit("error", {message: "Failed to process message"});
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
    res.send = function (body) {
        console.log(`${new Date().toISOString()} - Response ${res.statusCode} for ${req.method} ${req.url}`);
        return originalSend.call(this, body);
    };
    next();
});

app.use((err: Error, req: Request, res: Response, next: Function) => {
    console.error(`Server error: ${err.message}`);
    if (!res.headersSent) {
        res.status(500).json({error: "Internal server error"});
    }
});
