import { Router } from "express";
import { OAuth2Client } from "google-auth-library";
import jwt from "jsonwebtoken";
import { db } from "../db.js";

const router = Router();
const oauthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

router.post("/google", async (req, res) => {
  try {
    const { credential } = req.body || {};
    if (!credential) {
      return res.status(400).json({ error: "Missing credential" });
    }

    let ticket;
    try {
      ticket = await oauthClient.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
    } catch (err) {
      console.error("Google token verification failed:", err);
      return res.status(403).json({ error: "Invalid Google token" });
    }

    const payload = ticket.getPayload();
    if (!payload) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    const googleSub = payload.sub;
    const email = payload.email;

    // Firestore lookup
    const userRef = db.collection("users").doc(googleSub);
    const doc = await userRef.get();

    let user;
    if (!doc.exists) {
      try {
        await userRef.set({
          email,
          premium: false,
          created_at: new Date(),
        });
        user = { id: googleSub, email, premium: false };
      } catch (err) {
        console.error("Error creating user:", err);
        return res.status(500).json({ error: "Failed to create user" });
      }
    } else {
      user = { id: googleSub, ...doc.data() };
    }

    // Issue JWT
    let token;
    try {
      token = jwt.sign(
        { userId: user.id, email: user.email, premium: user.premium },
        process.env.JWT_SECRET,
        { expiresIn: "7d" }
      );
    } catch (err) {
      console.error("Error signing JWT:", err);
      return res.status(500).json({ error: "Failed to issue token" });
    }

    return res.json({ success: true, token });
  } catch (err) {
    console.error("Unexpected error in /auth/google:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
