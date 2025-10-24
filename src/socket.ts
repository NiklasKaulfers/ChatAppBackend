import jwt from "jsonwebtoken";
import { v4 as uuidV4 } from "uuid";
import {Server, Socket} from "socket.io";

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

interface CorsConfig {
    origin: string[];
    methods: string[];
    allowHeaders: string[]
}


export default class CSocket {
    private readonly io;
    private readonly roomUsers: RoomUsersMap = {}
    private readonly roomSecretKey: string;


    constructor(httpServer: any, roomSecretKey: string, corsConfig: CorsConfig) {
        this.io = new Server(httpServer, {
            cors: {
                origin: corsConfig.origin,
                methods: corsConfig.methods,
                allowedHeaders: corsConfig.allowHeaders,
            }
        });

        this.roomSecretKey = roomSecretKey;



        this.io.use((socket: Socket, next: any) => {
            const token = socket.handshake.auth.token;
            if (!token) {
                return next(new Error("Authentication error: Token missing"));
            }

            try {
                // Verify the token
                const decoded = jwt.verify(token, this.roomSecretKey) as { userId: string, roomId: string };
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

        this.io.on("connection", (socket: Socket) => {
            const authenticatedSocket = socket as AuthenticatedSocket;
            const userId = authenticatedSocket.user.id;
            const roomId = authenticatedSocket.user.roomId;

            console.log(`Client connected: ${socket.id}, User: ${userId}`);

            socket.join(roomId);

            if (!this.roomUsers[roomId]) {
                this.roomUsers[roomId] = new Set<string>();
            }
            this.roomUsers[roomId].add(userId);

            this.io.to(roomId).emit("userJoined", {
                user: userId,
                activeUsers: Array.from(this.roomUsers[roomId])
            });

            socket.on("message", async (data: { message: string }) => {
                const { message } = data;

                if (!message || message.trim() === "") {
                    socket.emit("error", { message: "Message cannot be empty" });
                    return;
                }

                try {
                    this.io.to(roomId).emit("message", {
                        id: uuidV4(),
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

                if (this.roomUsers[roomId]) {
                    this.roomUsers[roomId].delete(userId);

                    this.io.to(roomId).emit("userLeft", {
                        user: userId,
                        activeUsers: Array.from(this.roomUsers[roomId])
                    });

                    if (this.roomUsers[roomId].size === 0) {
                        delete this.roomUsers[roomId];
                    }
                }
            });
        });
    }
}



