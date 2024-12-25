import * as WebSocket from "ws";
import * as http from "http";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string; // Add an ID to each WebSocket connection
}

// Create HTTP server
const httpServer = http.createServer();
const server = new WebSocket.Server({ server: httpServer });

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});

// Generate a unique ID for each client
const generateClientId = () => Math.random().toString(36).substr(2, 9);

server.on("connection", (socket: ExtendedWebSocket) => {
    console.log("Client connected.");

    // Assign a unique ID to each client
    socket.id = generateClientId();
    socket.isAlive = true;

    // Respond to pong events to keep the connection alive
    socket.on("pong", () => {
        socket.isAlive = true;
    });

    // Broadcast incoming messages to all connected clients except the sender
    socket.on("message", (message: string) => {
        console.log(`Received message: ${message}`);
        server.clients.forEach((client) => {
            if (client !== socket && client.readyState === WebSocket.OPEN) {
                const broadcastMessage = JSON.stringify({
                    user: socket.id,
                    message,
                });
                client.send(broadcastMessage);
            }
        });
    });

    // Handle client disconnection
    socket.on("close", () => {
        console.log(`Client ${socket.id} disconnected.`);
    });

    // Log any errors
    socket.on("error", (error: Error) => {
        console.log(`Error: ${error.message}`);
    });

    // Send a structured welcome message to the client
    socket.send(JSON.stringify({ user: "Server", message: "Welcome to WS." }));
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
