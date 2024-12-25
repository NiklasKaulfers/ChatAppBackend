import * as WebSocket from "ws";
import * as http from "http";

export const chat = () =>{
    interface ExtendedWebSocket extends WebSocket {
        isAlive: boolean;
        id: string;
    }

    const httpServer = http.createServer();
    const server = new WebSocket.Server({server: httpServer});

    const PORT = process.env.PORT || 8080;
    httpServer.listen(PORT, () => {
        console.log(`Server is listening on port ${PORT}`);
    });

    const generateClientId = () => Math.random().toString(36).substring(2, 9);

    server.on("connection", (socket: ExtendedWebSocket) => {
        console.log("Client connected.");

        socket.id = generateClientId();
        socket.isAlive = true;

        socket.on("pong", () => {
            socket.isAlive = true;
        });

        // Broadcast message to all clients except the sender
        socket.on("message", (message: string) => {
            const messageString: string = JSON.parse(message).message
            console.log(`Received message: ${messageString}`);
            const broadcastMessage = JSON.stringify({
                user: socket.id,
                message: messageString,
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

        socket.send(JSON.stringify({user: "Server", message: "Welcome to WebSocket!"}));
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
}
