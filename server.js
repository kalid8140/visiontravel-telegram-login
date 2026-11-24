require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000
    }
  })
);

const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL;
const CLIENT_ID = process.env.TELEGRAM_CLIENT_ID;
const CLIENT_SECRET = process.env.TELEGRAM_CLIENT_SECRET;
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID;

const REDIRECT_URI = `${BASE_URL}/auth/callback`;

function randomString() {
  return crypto.randomBytes(32).toString("base64url");
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("base64url");
}

function escapeText(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    service: "Vision Travel Telegram Login"
  });
});

// Start Telegram Login
app.get("/auth/telegram", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET || !BASE_URL) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const state = randomString();
  const nonce = randomString();
  const verifier = randomString();

  req.session.oauth = {
    state,
    nonce,
    verifier
  };

  const authUrl = new URL("https://oauth.telegram.org/auth");

  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("scope", "openid profile");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("nonce", nonce);
  authUrl.searchParams.set("code_challenge", sha256(verifier));
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

// Telegram Login Callback
app.get("/auth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;
    const oauth = req.session.oauth;

    if (error) {
      return res.status(400).send("Telegram login was cancelled.");
    }

    if (
      !code ||
      !state ||
      !oauth ||
      state !== oauth.state
    ) {
      return res.status(400).send("Invalid login request.");
    }

    delete req.session.oauth;

    // Exchange authorization code for tokens
    const credentials = Buffer.from(
      `${CLIENT_ID}:${CLIENT_SECRET}`
    ).toString("base64");

    const tokenResponse = await fetch(
      "https://oauth.telegram.org/token",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Authorization: `Basic ${credentials}`
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: String(code),
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier: oauth.verifier
        })
      }
    );

    const tokens = await tokenResponse.json();

    if (!tokenResponse.ok || !tokens.id_token) {
      console.error("Telegram token exchange failed.");
      return res.status(401).send("Telegram authentication failed.");
    }

    // Verify Telegram's signed ID token
    const { createRemoteJWKSet, jwtVerify } =
      await import("jose");

    const JWKS = createRemoteJWKSet(
      new URL("https://oauth.telegram.org/.well-known/jwks.json")
    );

    const { payload } = await jwtVerify(
      tokens.id_token,
      JWKS,
      {
        issuer: "https://oauth.telegram.org",
        audience: String(CLIENT_ID)
      }
    );

    if (payload.nonce !== oauth.nonce) {
      return res.status(401).send("Invalid login verification.");
    }

    const telegramId = payload.id;

    if (!telegramId) {
      return res.status(401).send("Telegram user ID is missing.");
    }

    const name = payload.name || "Not provided";
    const username = payload.preferred_username || "Not provided";

    // Save authenticated user in session
    req.session.user = {
      telegramId: String(telegramId),
      name,
      username
    };

    // Notify website administrator
    if (BOT_TOKEN && ADMIN_CHAT_ID) {
      const message =
        "🔐 VISION TRAVEL - NEW LOGIN\n\n" +
        `Name: ${escapeText(name)}\n` +
        `Username: ${escapeText(username)}\n` +
        `Telegram ID: ${telegramId}\n\n` +
        "Authentication: Verified by Telegram";

      const telegramResponse = await fetch(
        `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            chat_id: ADMIN_CHAT_ID,
            text: message,
            parse_mode: "HTML"
          })
        }
      );

      if (!telegramResponse.ok) {
        console.error("Administrator notification failed.");
      }
    }

    res.redirect("/?login=success");

  } catch (error) {
    console.error("Login error:", error.message);
    res.status(500).send("Login could not be completed.");
  }
});

// Current logged-in user
app.get("/me", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    user: req.session.user
  });
});

// Logout
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

app.listen(PORT, () => {
  console.log(`Vision Travel Login running on port ${PORT}`);
});