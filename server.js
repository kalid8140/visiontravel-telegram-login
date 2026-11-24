require("dotenv").config();

const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

const PORT = process.env.PORT || 10000;

const BASE_URL = (process.env.BASE_URL || "").replace(/\/+$/, "");
const FRONTEND_URL =
  process.env.FRONTEND_URL ||
  "https://polite-melomakarona-fe538c.netlify.app";

const CLIENT_ID = process.env.TELEGRAM_CLIENT_ID;
const CLIENT_SECRET = process.env.TELEGRAM_CLIENT_SECRET;
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_CHAT_ID = process.env.ADMIN_CHAT_ID;
const SESSION_SECRET = process.env.SESSION_SECRET;

const REDIRECT_URI = `${BASE_URL}/auth/callback`;
const WEBHOOK_PATH = "/telegram/webhook";

const WEBHOOK_SECRET = crypto
  .createHash("sha256")
  .update(`${BOT_TOKEN || ""}${SESSION_SECRET || ""}`)
  .digest("hex");

if (!SESSION_SECRET) {
  console.error("ERROR: SESSION_SECRET is missing.");
  process.exit(1);
}

if (!BASE_URL || !CLIENT_ID || !CLIENT_SECRET) {
  console.error("ERROR: Telegram Login configuration is missing.");
  process.exit(1);
}

app.use(
  session({
    name: "visiontravel.sid",
    secret: SESSION_SECRET,
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

// Generate secure random values
function randomString() {
  return crypto.randomBytes(32).toString("base64url");
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(value)
    .digest("base64url");
}

// Escape Telegram HTML
function escapeText(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Telegram API helper
async function telegram(method, data = {}) {
  if (!BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is missing.");
  }

  const response = await fetch(
    `https://api.telegram.org/bot${BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    }
  );

  const result = await response.json();

  if (!response.ok || !result.ok) {
    throw new Error(
      result.description || `Telegram API error ${response.status}`
    );
  }

  return result;
}

// Send notification to administrator
async function notifyAdministrator(user) {
  if (!BOT_TOKEN || !ADMIN_CHAT_ID) {
    console.error("Missing BOT_TOKEN or ADMIN_CHAT_ID.");
    return;
  }

  const message =
    "🔐 <b>VISION TRAVEL - NEW LOGIN</b>\n\n" +
    `Name: ${escapeText(user.name)}\n` +
    `Username: ${escapeText(user.username)}\n` +
    `Telegram ID: <code>${escapeText(user.telegramId)}</code>\n\n` +
    "Authentication: Verified by Telegram";

  try {
    await telegram("sendMessage", {
      chat_id: ADMIN_CHAT_ID,
      text: message,
      parse_mode: "HTML"
    });

    console.log("Administrator notification sent successfully.");
  } catch (error) {
    console.error(
      "Administrator notification failed:",
      error.message
    );
  }
}

// Health check
app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    service: "Vision Travel Telegram Login"
  });
});

// Telegram bot webhook
app.post(WEBHOOK_PATH, async (req, res) => {
  const receivedSecret =
    req.get("X-Telegram-Bot-Api-Secret-Token");

  if (
    !WEBHOOK_SECRET ||
    receivedSecret !== WEBHOOK_SECRET
  ) {
    return res.sendStatus(403);
  }

  const message = req.body?.message;
  const chatId = message?.chat?.id;
  const text = message?.text || "";

  res.sendStatus(200);

  if (!chatId || !text) return;

  try {
    if (text.startsWith("/start")) {
      await telegram("sendMessage", {
        chat_id: chatId,
        text:
          "Welcome to Vision Travel! ✈️\n\n" +
          "Your bot is now active.\n\n" +
          `Your Chat ID: ${chatId}\n\n` +
          "Use this number as ADMIN_CHAT_ID in Render."
      });

      console.log("Bot /start answered. Chat ID:", chatId);

    } else if (text.startsWith("/help")) {
      await telegram("sendMessage", {
        chat_id: chatId,
        text: "Vision Travel Bot is working. Send /start to see your Chat ID."
      });
    }
  } catch (error) {
    console.error("Bot reply error:", error.message);
  }
});

// Start Telegram Login
app.get("/auth/telegram", (req, res) => {
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
      return res.status(400).send(
        "Telegram login was cancelled."
      );
    }

    if (
      !code ||
      !state ||
      !oauth ||
      state !== oauth.state
    ) {
      return res.status(400).send(
        "Invalid login request. Please try again."
      );
    }

    delete req.session.oauth;

    // Exchange authorization code
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
      console.error(
        "Telegram token exchange failed:",
        tokens.error_description || tokens.error || "Unknown error"
      );

      return res.status(401).send(
        "Telegram authentication failed."
      );
    }

    // Verify Telegram ID token
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
      return res.status(401).send(
        "Invalid login verification."
      );
    }

    const telegramId = payload.id || payload.sub;

    if (!telegramId) {
      return res.status(401).send(
        "Telegram user ID is missing."
      );
    }

    const user = {
      telegramId: String(telegramId),
      name: payload.name || "Not provided",
      username: payload.preferred_username || "Not provided"
    };

    // Save login session
    req.session.user = user;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    // Notify administrator
    await notifyAdministrator(user);

    console.log("Telegram login successful:", user.telegramId);

    res.redirect(`${FRONTEND_URL}/?login=success`);

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).send(
      "Login could not be completed. Please try again."
    );
  }
});

// Check logged-in user
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
    res.clearCookie("visiontravel.sid");
    res.redirect(FRONTEND_URL);
  });
});

// Start server and configure webhook
app.listen(PORT, async () => {
  console.log(
    `Vision Travel Login running on port ${PORT}`
  );

  if (!BOT_TOKEN) {
    console.error("TELEGRAM_BOT_TOKEN is missing.");
    return;
  }

  try {
    const botInfo = await telegram("getMe");

    console.log(
      "Telegram bot connected:",
      botInfo.result.username
    );

    await telegram("setWebhook", {
      url: `${BASE_URL}${WEBHOOK_PATH}`,
      secret_token: WEBHOOK_SECRET,
      allowed_updates: ["message"]
    });

    console.log("Telegram webhook configured successfully.");

  } catch (error) {
    console.error(
      "Telegram bot setup failed:",
      error.message
    );
  }
});