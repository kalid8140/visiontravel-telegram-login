const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);
app.use(express.json());

const PORT = process.env.PORT || 10000;

const BASE_URL = (
  process.env.BASE_URL ||
  "https://visiontravel-telegram-login.onrender.com"
).replace(/\/+$/, "");

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  "https://polite-melomakarona-fe538c.netlify.app"
).replace(/\/+$/, "");

const CALLBACK_URL = `${BASE_URL}/auth/callback`;

const {
  TELEGRAM_CLIENT_ID,
  TELEGRAM_CLIENT_SECRET,
  TELEGRAM_BOT_TOKEN,
  ADMIN_CHAT_ID,
  SESSION_SECRET,
  WEBHOOK_SECRET,
  WEBHOOK_SETUP_SECRET
} = process.env;


// ===============================
// SESSION
// ===============================

app.use(
  session({
    name: "visiontravel.sid",
    secret: SESSION_SECRET || "change-this-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: "auto",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);


// ===============================
// HELPERS
// ===============================

function randomString(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  const first = Buffer.from(a);
  const second = Buffer.from(b);

  return (
    first.length === second.length &&
    crypto.timingSafeEqual(first, second)
  );
}

async function telegramApi(method, data = {}) {
  if (!TELEGRAM_BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is missing");
  }

  const response = await fetch(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(15000)
    }
  );

  const result = await response.json();

  if (!response.ok || !result.ok) {
    const retry = result.parameters?.retry_after;

    throw new Error(
      `${method}: ${result.description || response.status}` +
      (retry ? `; retry after ${retry} seconds` : "")
    );
  }

  return result.result;
}


// ===============================
// SEND LOGIN NOTIFICATION
// ===============================

async function notifyAdmin(user) {
  if (!ADMIN_CHAT_ID) {
    throw new Error("ADMIN_CHAT_ID is missing");
  }

  const name =
    user.name ||
    [user.given_name, user.family_name].filter(Boolean).join(" ") ||
    "Not provided";

  const username = user.preferred_username
    ? "@" + user.preferred_username
    : "Not provided";

  const telegramId = user.id || user.sub || "Not provided";

  const message = [
    "✅ VISION TRAVEL - NEW LOGIN",
    "",
    `Name: ${name}`,
    `Username: ${username}`,
    `Telegram ID: ${telegramId}`,
    `Time: ${new Date().toISOString()}`
  ].join("\n");

  await telegramApi("sendMessage", {
    chat_id: ADMIN_CHAT_ID,
    text: message
  });
}


// ===============================
// HOME PAGE
// ===============================

app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Vision Travel</title>
      <style>
        body {
          font-family: Arial;
          text-align: center;
          padding: 50px 15px;
          background: #f4f6fa;
        }
        a {
          display: inline-block;
          padding: 15px 25px;
          background: #1688d4;
          color: white;
          text-decoration: none;
          border-radius: 8px;
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <h1>Vision Travel</h1>
      <p>Secure login with Telegram</p>
      <a href="/auth/telegram">Log in with Telegram</a>
    </body>
    </html>
  `);
});


// ===============================
// HEALTH CHECK
// ===============================

app.get("/health", (req, res) => {
  res.json({
    status: "OK",
    service: "Vision Travel Telegram Login"
  });
});


// ===============================
// TELEGRAM LOGIN START
// ===============================

app.get("/auth/telegram", (req, res) => {
  if (
    !TELEGRAM_CLIENT_ID ||
    !TELEGRAM_CLIENT_SECRET ||
    !SESSION_SECRET
  ) {
    return res.status(500).send("Server configuration is incomplete.");
  }

  const state = randomString();
  const nonce = randomString();
  const verifier = randomString(48);

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  req.session.telegramOAuth = {
    state,
    nonce,
    verifier,
    createdAt: Date.now()
  };

  const authUrl = new URL("https://oauth.telegram.org/auth");

  authUrl.search = new URLSearchParams({
    client_id: TELEGRAM_CLIENT_ID,
    redirect_uri: CALLBACK_URL,
    response_type: "code",
    scope: "openid profile",
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: "S256"
  }).toString();

  req.session.save((error) => {
    if (error) {
      console.error("Session save error:", error.message);
      return res.status(500).send("Could not start login.");
    }

    res.redirect(authUrl.toString());
  });
});


// ===============================
// TELEGRAM LOGIN CALLBACK
// ===============================

app.get("/auth/callback", async (req, res) => {
  try {
    if (req.query.error) {
      return res.status(400).send(
        "Telegram login was not completed."
      );
    }

    const saved = req.session.telegramOAuth;
    const { code, state } = req.query;

    if (
      !saved ||
      !code ||
      !state ||
      !safeEqual(String(state), saved.state)
    ) {
      return res.status(400).send(
        "Login session expired. Please try again."
      );
    }

    if (Date.now() - saved.createdAt > 10 * 60 * 1000) {
      delete req.session.telegramOAuth;
      return res.status(400).send("Login session expired.");
    }

    const credentials = Buffer.from(
      `${TELEGRAM_CLIENT_ID}:${TELEGRAM_CLIENT_SECRET}`
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
          redirect_uri: CALLBACK_URL,
          client_id: TELEGRAM_CLIENT_ID,
          code_verifier: saved.verifier
        }),
        signal: AbortSignal.timeout(15000)
      }
    );

    const tokenData = await tokenResponse.json();

    if (!tokenResponse.ok || !tokenData.id_token) {
      console.error(
        "Token exchange failed:",
        tokenData.error_description ||
        tokenData.error ||
        tokenResponse.status
      );

      return res.status(502).send(
        "Telegram login verification failed."
      );
    }

    // jose v6 is ESM, so use dynamic import.
    const { createRemoteJWKSet, jwtVerify } =
      await import("jose");

    const jwks = createRemoteJWKSet(
      new URL(
        "https://oauth.telegram.org/.well-known/jwks.json"
      )
    );

    const { payload } = await jwtVerify(
      tokenData.id_token,
      jwks,
      {
        issuer: "https://oauth.telegram.org",
        audience: String(TELEGRAM_CLIENT_ID)
      }
    );

    if (
      !payload.nonce ||
      !safeEqual(String(payload.nonce), saved.nonce)
    ) {
      return res.status(401).send(
        "Telegram security verification failed."
      );
    }

    const user = {
      id: payload.id || payload.sub,
      sub: payload.sub,
      name: payload.name,
      given_name: payload.given_name,
      family_name: payload.family_name,
      preferred_username: payload.preferred_username,
      picture: payload.picture
    };

    req.session.user = user;
    delete req.session.telegramOAuth;

    // Notify administrator.
    // If notification fails, keep the user's login session.
    try {
      await notifyAdmin(user);
      console.log("Administrator notification sent successfully.");
    } catch (error) {
      console.error(
        "Administrator notification failed:",
        error.message
      );
    }

    req.session.save((error) => {
      if (error) {
        console.error("Session save failed:", error.message);
        return res.status(500).send("Could not save login session.");
      }

      res.redirect(`${FRONTEND_URL}/?telegram_login=success`);
    });

  } catch (error) {
    console.error("OAuth callback failed:", error.message);
    res.status(500).send("Telegram login failed.");
  }
});


// ===============================
// TELEGRAM BOT WEBHOOK
// ===============================

app.post("/telegram/webhook", async (req, res) => {
  const receivedSecret =
    req.get("X-Telegram-Bot-Api-Secret-Token") || "";

  if (!safeEqual(receivedSecret, WEBHOOK_SECRET || "")) {
    return res.sendStatus(401);
  }

  // Respond to Telegram immediately.
  res.sendStatus(200);

  const message = req.body?.message;
  const chatId = message?.chat?.id;
  const text = message?.text || "";

  if (!chatId || !text.startsWith("/")) {
    return;
  }

  try {
    if (text.startsWith("/start")) {
      await telegramApi("sendMessage", {
        chat_id: chatId,
        text:
          "Welcome to Vision Travel! ✅\n\n" +
          "Your Telegram bot is active.\n" +
          "You can use Telegram to log in to the Vision Travel website."
      });
    }

    if (text.startsWith("/help")) {
      await telegramApi("sendMessage", {
        chat_id: chatId,
        text:
          "Vision Travel Bot\n\n" +
          "Use the Log in with Telegram button on the website."
      });
    }

  } catch (error) {
    console.error("Bot reply failed:", error.message);
  }
});


// ===============================
// SET WEBHOOK ONCE
// ===============================

app.get("/admin/setup-webhook", async (req, res) => {
  const suppliedKey = String(req.query.key || "");

  if (
    !WEBHOOK_SETUP_SECRET ||
    !safeEqual(suppliedKey, WEBHOOK_SETUP_SECRET)
  ) {
    return res.sendStatus(404);
  }

  try {
    await telegramApi("setWebhook", {
      url: `${BASE_URL}/telegram/webhook`,
      secret_token: WEBHOOK_SECRET,
      allowed_updates: ["message"],
      drop_pending_updates: false
    });

    console.log("Telegram webhook configured successfully.");

    res.send(
      "Webhook configured successfully. " +
      "Remove WEBHOOK_SETUP_SECRET from Render Environment and redeploy."
    );

  } catch (error) {
    console.error("Webhook setup failed:", error.message);
    res.status(502).send("Webhook setup failed: " + error.message);
  }
});


// ===============================
// USER SESSION
// ===============================

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


// ===============================
// LOGOUT
// ===============================

app.post("/logout", (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      return res.status(500).json({
        error: "Logout failed"
      });
    }

    res.clearCookie("visiontravel.sid");

    res.json({
      success: true
    });
  });
});


// ===============================
// ERROR HANDLER
// ===============================

app.use((error, req, res, next) => {
  console.error("Server error:", error.message);
  res.status(500).send("Internal server error.");
});


// ===============================
// START SERVER
// ===============================

app.listen(PORT, () => {
  console.log(
    `Vision Travel Login running on port ${PORT}`
  );

  console.log(
    "Server started. Webhook will not be reset on startup."
  );
});