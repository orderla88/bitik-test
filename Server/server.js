import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import "dotenv/config";
import authRouter from "./Routes/auth.js";
import { db } from "./db.js";
import jwt from "jsonwebtoken";


const FRONTEND_ORIGIN = "http://localhost:5500";
const app = express();
app.use(cookieParser());
app.use(express.json());
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  })
);
app.use("/auth", authRouter);

app.get("/me", async (req, res) => {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      return res.status(401).json({ error: "Missing Authorization header" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ error: "Missing token" });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: "Invalid or expired token" });
    }

    const userRef = db.collection("users").doc(decoded.userId);
    const doc = await userRef.get();

    if (!doc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.json({ user: { id: doc.id, ...doc.data() } });
  } catch (err) {
    console.error("Unexpected error in /me:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
