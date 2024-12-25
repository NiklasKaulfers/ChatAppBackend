import * as WebSocket from "ws";
import * as http from "http";

interface ExtendedWebSocket extends WebSocket {
    isAlive: boolean;
    id: string; // Add an ID to each WebSocket connection
}

const httpServer = http.createServer();
const server = new WebSocket.Server({ server: httpServer });

const PORT = process.env.PORT || 8080;
httpServer.listen(PORT, () => {
    console.log(`Server is listening on port ${PORT}`);
});

const generateClientId = () => Math.random().toString(36).substr(2, 9);

server.on("connection", (socket: ExtendedWebSocket) => {
    console.log("Client connected.");

    socket.id = generateClientId();
    socket.isAlive = true;

    socket.on("pong", () => {
        socket.isAlive = true;
    });

    // Broadcast message to all clients except the sender
    socket.on("message", (message: string) => {
        console.log(`Received message: ${message}`);
        const broadcastMessage = JSON.stringify({
            user: socket.id,
            message: message,
        });
        console.log("Broadcasting message:", broadcastMessage);
        server.clients.forEach((client) => {
            if (client !== socket && client.readyState === WebSocket.OPEN) {
                client.send(broadcastMessage);
            }
        });
    });

    socket.on("close", () => {
        console.log("Client disconnected.");
    });

    socket.on("error", (error: Error) => {
        console.log(`Error: ${error.message}`);
    });

    socket.send(JSON.stringify({ user: "Server", message: "Welcome to WebSocket!" }));
});

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
