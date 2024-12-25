import * as WebSocket from "ws";



const server = new WebSocket.Server;

server.on("connection", (socket:WebSocket) => {
    console.log("Client connected.");
    socket.on("message", (message) =>{
        console.log(`Received message ${message}`);
        socket.send(`Message: ${message}`);
    });
    socket.on("close", () =>{
        console.log("Client disconnected.");
    });
    socket.on("error", (error:Error) =>{
        console.log(`Error: ${error.message}`)
    });
    socket.send("Welcome to WS.")
})