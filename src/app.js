import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { pool } from "./db/db.js";
import {
  initCookieAuth,
  signInUser,
  signOutUser,
  requiresAuthentication,
} from "./auth.js";

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

if (!process.env.COOKIE_KEY) {
  if (isProduction) {
    throw new Error("Na Renderu mora biti postavljena varijabla COOKIE_KEY.");
  }

  // Samo praktična lokalna vrijednost. U produkciji se mora postaviti vlastiti ključ.
  process.env.COOKIE_KEY = "lokalni-demo-cookie-key-promijeni-u-produkciji";
}

// Render terminira HTTPS na proxyju. To je potrebno za Secure cookie.
app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

// Signed cookies + req.user middleware iz auth.js.
initCookieAuth(app, "/");

// Postavka je globalna za edukacijsku demonstraciju i vraća se na sigurno
// nakon ponovnog pokretanja besplatne Render instance.
let csrfVulnerabilityEnabled = false;

function isValidCsrfToken(req) {
  const received = req.body?.csrfToken;
  const expected = req.csrfToken;

  if (typeof received !== "string" || typeof expected !== "string") {
    return false;
  }

  const receivedBuffer = Buffer.from(received);
  const expectedBuffer = Buffer.from(expected);

  return (
    receivedBuffer.length === expectedBuffer.length &&
    crypto.timingSafeEqual(receivedBuffer, expectedBuffer)
  );
}

async function renderPage(req, res, data = {}) {
  let users = [];
  let usersError = null;
  let currentUser = null;

  try {
    const usersResult = await pool.query(
      "SELECT id, username FROM users ORDER BY id",
    );
    users = usersResult.rows;

    if (req.user?.username) {
      const currentResult = await pool.query(
        "SELECT id, username FROM users WHERE username = $1 ORDER BY id LIMIT 1",
        [req.user.username],
      );
      currentUser = currentResult.rows[0] || null;
    }
  } catch (error) {
    console.error("Greška pri dohvaćanju korisnika:", error.message);
    usersError = isProduction
      ? "Nije moguće dohvatiti korisnike iz baze."
      : error.message;
  }

  const appUrl = `${req.protocol}://${req.get("host")}`;
  const attackerUrl =
    process.env.ATTACKER_URL || (isProduction ? "" : "http://localhost:4000");
  const attackerLink = attackerUrl
    ? `${attackerUrl.replace(/\/$/, "")}/?target=${encodeURIComponent(appUrl)}`
    : "";

  return res.render("index", {
    sqlInjectionEnabled: false,
    username: "",
    loginResult: null,
    sqlPreview: null,
    databaseError: null,
    currentUser,
    csrfVulnerabilityEnabled,
    csrfToken: req.csrfToken || "",
    users,
    usersError,
    attackerLink,
    appUrl,
    notice: null,
    noticeType: "neutral",
    ...data,
  });
}

async function rejectInvalidCsrf(req, res) {
  res.status(403);
  await renderPage(req, res, {
    notice:
      "Zahtjev je odbijen: nedostaje ili nije valjan CSRF token. Račun nije obrisan.",
    noticeType: "error",
  });
}

app.get("/", (req, res) => {
  return renderPage(req, res);
});

// Prijava i SQL Injection demonstracija.
// Kod uspješne prijave postavljamo potpisane user i csrfToken cookieje.
app.post("/demo", async (req, res) => {
  const username = String(req.body.username ?? "");
  const password = String(req.body.password ?? "");
  const sqlInjectionEnabled = req.body.sqlInjectionEnabled === "on";

  let loginResult = null;
  let sqlPreview = null;
  let databaseError = null;
  let signedInUser = null;
  let csrfToken = "";

  try {
    let result;

    if (sqlInjectionEnabled) {
      // NAMJERNO RANJIVO: korisnički unos izravno se spaja u SQL upit.
      const sql = `SELECT id, username FROM users WHERE username = '${username}' AND password = '${password}' ORDER BY id`;
      result = await pool.query(sql);
      sqlPreview = `SELECT id, username FROM users WHERE username = '${username}' AND password = '********' ORDER BY id`;
    } else {
      // SIGURNO: parametri se šalju odvojeno od SQL naredbe.
      const sql =
        "SELECT id, username FROM users WHERE username = $1 AND password = $2 ORDER BY id";
      result = await pool.query(sql, [username, password]);
      sqlPreview = sql;
    }

    result.rows.sort((a, b) => Number(a.id) - Number(b.id));

    loginResult = {
      success: result.rows.length > 0,
      users: result.rows,
      count: result.rows.length,
    };

    if (result.rows.length > 0) {
      signedInUser = result.rows[0];
      csrfToken = signInUser(res, signedInUser.username);
    }
  } catch (error) {
    console.error("Greška pri izvođenju SQL upita:", error);
    databaseError = isProduction
      ? "Došlo je do pogreške pri komunikaciji s bazom podataka."
      : error.message;
  }

  return renderPage(req, res, {
    sqlInjectionEnabled,
    username,
    loginResult,
    sqlPreview,
    databaseError,
    currentUser: signedInUser,
    csrfToken,
  });
});

// Prekidač je dostupan samo prijavljenom korisniku i uvijek traži valjani token.
app.post("/csrf-mode", requiresAuthentication, async (req, res) => {
  if (!isValidCsrfToken(req)) {
    return rejectInvalidCsrf(req, res);
  }

  csrfVulnerabilityEnabled = req.body.csrfVulnerabilityEnabled === "on";
  return res.redirect("/");
});

// Napadačka stranica šalje POST bez csrfToken polja.
app.post("/account/delete", requiresAuthentication, async (req, res) => {
  if (!csrfVulnerabilityEnabled && !isValidCsrfToken(req)) {
    return rejectInvalidCsrf(req, res);
  }

  try {
    // Cookie sadrži samo korisničko ime (kao u priloženom primjeru).
    // Brišemo prvi zapis s tim korisničkim imenom, a ne ID koji šalje klijent.
    const deleted = await pool.query(
      `DELETE FROM users
       WHERE id = (
         SELECT id FROM users WHERE username = $1 ORDER BY id LIMIT 1
       )
       RETURNING id, username`,
      [req.user.username],
    );

    if (deleted.rowCount === 0) {
      return renderPage(req, res, {
        notice: "Korisnički račun nije pronađen. Možda je već obrisan.",
        noticeType: "error",
      });
    }

    const deletedUsername = deleted.rows[0].username;
    signOutUser(res);

    return renderPage(req, res, {
      currentUser: null,
      csrfToken: "",
      notice: `CSRF napad je uspio: račun '${deletedUsername}' obrisan je iz baze podataka.`,
      noticeType: "success",
    });
  } catch (error) {
    console.error("Greška pri brisanju korisničkog računa:", error);
    return renderPage(req, res, {
      notice: isProduction
        ? "Došlo je do pogreške pri brisanju računa."
        : error.message,
      noticeType: "error",
    });
  }
});

app.post("/logout", requiresAuthentication, async (req, res) => {
  if (!isValidCsrfToken(req)) {
    return rejectInvalidCsrf(req, res);
  }

  signOutUser(res);
  return renderPage(req, res, {
    currentUser: null,
    csrfToken: "",
    notice: "Uspješno si odjavljen/a.",
    noticeType: "success",
  });
});

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`Aplikacija je pokrenuta na portu ${PORT}`);
});

async function shutDown() {
  console.log("Zaustavljanje aplikacije...");
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}

process.on("SIGINT", shutDown);
process.on("SIGTERM", shutDown);
