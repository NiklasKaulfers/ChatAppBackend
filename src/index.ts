import * as WebSocket from "ws";



const server = new WebSocket.Server;

server.on("connection", (socket:WebSocket) => {
    console.log("Client connected.");
    socket.on("message", (message) =>{
        server.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(message);
            }
        });
    });
    socket.on("close", () =>{
        console.log("Client disconnected.");
    });
    socket.on("error", (error:Error) =>{
        console.log(`Error: ${error.message}`)
    });
    socket.send("Welcome to WS.")
    setInterval(() => {
        server.clients.forEach((client) => {
            if (client.readyState === WebSocket.OPEN) {
                client.ping(); // Send ping
            }
        });
    }, 30000);
})