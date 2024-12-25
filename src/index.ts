import * as WebSocket from "ws";
import * as http from "http";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
}

const httpServer = http.createServer();
const server = new WebSocket.Server({ server: httpServer });

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});


server.on("connection", (socket: ExtendedWebSocket) => {
    console.log("Client connected.");

    socket.isAlive = true;

    // Respond to pong events to keep the connection alive
    socket.on("pong", () => {
        socket.isAlive = true;
    });

    // Broadcast incoming messages to all connected clients except the sender
    socket.on("message", (message) => {
        server.clients.forEach((client) => {
            if (client !== socket && client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });

    // Handle client disconnection
    socket.on("close", () => {
        console.log("Client disconnected.");
    });

    // Log any errors
    socket.on("error", (error: Error) => {
        console.log(`Error: ${error.message}`);
    });

    // Send a welcome message to the client
    socket.send("Welcome to WS.");
});

// Periodically ping clients to ensure they're alive
setInterval(() => {
    server.clients.forEach((client) => {
        const extendedClient = client as ExtendedWebSocket;

        if (!extendedClient.isAlive) {
            console.log("Terminating inactive client");
            return client.terminate();
        }

        extendedClient.isAlive = false;
        client.ping();
    });
}, 30000);
