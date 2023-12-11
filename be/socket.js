const express = require("express");
const app = express();
const http = require("http");
const server = http.createServer(app);
const io = require("socket.io")(server, {
  cors: {
    origin: "http://localhost:3000",
    method: ["GET", "POST"],
  },
});

const PORT = 4000;

io.on("connection", (socket) => {
  console.log("Truy cập thành công " + socket.id);

  socket.on("join", ({ room }) => {
    socket.join(room, () => {
      console.log(`${socket.id} truy cập vào phòng ${room}`);
    });
  });

  socket.on("comment", ({ room, ...commentData }) => {
    socket.to(room).emit("localUserComment", commentData);
  });

  socket.on("deleteMsg", ({ commentId, room }) => {
    socket.to(room).emit("receiveDelete", { commentId });
  });

  socket.on("commentLike", ({ room, commentId, localUserId, commentLikes }) => {
    socket
      .to(room)
      .emit("receiveLike", { commentId, localUserId, commentLikes });
  });

  socket.on("disconnect", () => {
    console.log(socket.id + " ngắt kết nối");
  });
});

server.listen(PORT, () => {
  console.log("Socket io running on port " + PORT);
});
