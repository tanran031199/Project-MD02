require("dotenv").config();
const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const server = jsonServer.create();
const db = JSON.parse(fs.readFileSync("./db.json", "utf-8"));
const PORT = 4500;
const SCRET_KEY = process.env.SCRET_KEY;
const REFRESH_SCRET_KEY = process.env.REFRESH_SCRET_KEY;
const expiresIn = "60s";

server.use(bodyParser.urlencoded({ extended: false }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const createAcessToken = (payload) => {
  return jwt.sign(payload, SCRET_KEY, { expiresIn });
};

const createRefreshToken = (payload) => {
  return jwt.sign(payload, REFRESH_SCRET_KEY, { expiresIn: "365d" });
};

const isAuthenticated = ({ email, password }) => {
  return db.users.find((u) => {
    return u.email === email && bcrypt.compareSync(password, u.password);
  });
};

server.post("/api/auth/register", (req, res) => {
  const { email, password, uid, role, ...other } = req.body;
  const user = isAuthenticated({ email, password });
  const isEmailExist = db.users.find((u) => u.email === email);

  if (isEmailExist || isAuthenticated({ email, password })) {
    const status = 401;
    const message = "Tài khoản đã tồn tại!";
    res.status(status).json({ status, message });
    return;
  }

  fs.readFile("./db.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      res.status(status).json({ status, message });
      return;
    }

    data = JSON.parse(data.toString());

    let lastDbUserId;

    if (data.users.length > 0) {
      lastDbUserId = data.users[data.users.length - 1].id;
    } else {
      lastDbUserId = 0;
    }

    const hashPassword = bcrypt.hashSync(password, 10);

    data.users = [
      ...data.users,
      {
        id: lastDbUserId + 1,
        email,
        password: hashPassword,
        uid,
        role,
        ...other,
      },
    ];

    fs.writeFile("./db.json", JSON.stringify(data), (err, result) => {
      if (err) {
        const status = 401;
        const message = err;
        res.status(status).json({ status, message });
        return;
      }
    });
  });

  const accessToken = createAcessToken({ email, uid, role });
  const refreshToken = createRefreshToken({ email, uid, role });

  const response = { email, uid, role, accessToken, refreshToken };

  res.status(200).json(response);
});

server.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = isAuthenticated({ email, password });

  if (user.status === "blocked") {
    const status = 401;
    const message = "Tài khoản của bạn đã bị khóa!!! Donate đi thì mở khóa cho";
    return res.status(status).json({ status, message });
  }

  console.log(user);

  if (!isAuthenticated({ email, password })) {
    const status = 401;
    const message = "Tài khoản hoặc mật khẩu không chính xác!";
    return res.status(status).json({ status, message });
  }

  fs.readFile("./db.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      return res.status(status).json({ status, message });
    }

    data = JSON.parse(data.toString());

    const userIndex = data.users.findIndex((u) => u.uid === user.uid);

    if (userIndex === -1) {
      const status = 401;
      const message = "Tài khoản không tồn tại";
      return res.status(status).json({ status, message });
    }

    data.users[userIndex] = { ...data.users[userIndex], status: "active" };

    fs.writeFile("./db.json", JSON.stringify(data), (err, result) => {
      if (err) {
        const status = 401;
        const message = err;
        return res.status(status).json({ status, message });
      }
    });
  });

  const accessToken = createAcessToken({
    email,
    uid: user.uid,
    role: user.role,
  });
  const refreshToken = createRefreshToken({
    email,
    uid: user.uid,
    role: user.role,
  });

  const response = { ...user, accessToken, refreshToken };

  res.status(200).json(response);
});

server.get("/api/auth/refresh", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  const refreshToken = bearerHeader.split(" ")[1];

  if (!refreshToken) {
    const status = 401;
    const message = "Chưa đăng nhập hoặc đăng ký";
    return res.status(status).json({ status, message });
  }

  jwt.verify(refreshToken, REFRESH_SCRET_KEY, (err, decoded) => {
    if (err) {
      const status = 401;
      const message = "Token không hợp lệ";
      return res.status(status).json({ status, message });
    }

    const newAccessToken = createAcessToken({
      email: decoded.email,
      uid: decoded.uid,
      role: decoded.role,
    });
    const newRefreshToken = createRefreshToken({
      email: decoded.email,
      uid: decoded.uid,
      role: decoded.role,
    });

    res.status(200).json({
      newAccessToken,
      newRefreshToken,
      uid: decoded.uid,
      role: decoded.role,
    });
  });
});

server.put("/api/auth/change-info", (req, res) => {
  const { email, password, uid, ...newInfo } = req.body;

  fs.readFile("./db.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      return res.status(status).json({ status, message });
    }

    data = JSON.parse(data.toString());

    const userIndex = data.users.findIndex((u) => u.uid === uid);

    const oldInfo = data.users[userIndex];

    if (password && !bcrypt.compare(password, oldInfo.password)) {
      const status = 401;
      const message = "Mật khẩu không có thay đổi!!!";
      return res.status(401).json({ status, message });
    }

    let hashPassword = oldInfo.password;

    if (password) {
      bcrypt.hashSync(password, 10);
    }

    if (userIndex === -1) {
      const status = 401;
      const message = "Người dùng không tồn tại!!!";
      return res.status(status).json({ status, message });
    }

    data.users[userIndex] = {
      password: hashPassword,
      email,
      uid,
      ...newInfo,
    };

    fs.writeFile("./db.json", JSON.stringify(data), (err, result) => {
      if (err) {
        const status = 401;
        const message = err;
        return res.status(status).json({ status, message });
      }
    });

    const accessToken = createAcessToken({ email, uid, role: newInfo.role });
    const refreshToken = createRefreshToken({ email, uid, role: newInfo.role });

    res.status(200).json({
      accessToken,
      refreshToken,
      password: hashPassword,
      email,
      uid,
      ...newInfo,
    });
  });
});

server.get("/api/auth/users", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  const accessToken = bearerHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(accessToken, SCRET_KEY);

    if (decoded.role === "admin") {
      fs.readFile("./db.json", (err, data) => {
        if (err) {
          const status = 401;
          const message = err;
          return res.status(status).json({ status, message });
        }

        data = JSON.parse(data.toString());

        res.status(200).json(data.users);
      });
    }
  } catch (err) {
    if (err instanceof jwt.TokenExpiredError) {
      const status = 401;
      const message = "Token không hợp lệ!!";
      return res.status(status).json({ status, message });
    }
  }
});

server.delete("/api/posts/delete", (req, res) => {
  const postId = req.headers.postid;
  console.log(postId);

  if (!postId) {
    const status = 401;
    const message = "Id bài post không tồn tại";
    return res.status(status).json({ status, message });
  }

  fs.readFile("./db.json", (err, data) => {
    if (err) {
      const status = 401;
      const message = err;
      return res.status(status).json({ status, message });
    }

    data = JSON.parse(data);

    data.posts = data.posts.filter((p) => p.postId !== postId);

    fs.writeFile("./db.json", JSON.stringify(data), (err) => {
      if (err) {
        const status = 500;
        const message = "Lỗi khi ghi dữ liệu vào tệp JSON";
        return res.status(status).json({ status, message });
      }

      res.status(200).json({ posts: data.posts });
    });
  });
});

server.listen(PORT, () => {
  console.log("Jwt running on port " + PORT);
});
