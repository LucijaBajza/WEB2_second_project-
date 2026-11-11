import cookieParser from "cookie-parser";
import { randomBytes } from "node:crypto";

let loginUrl = "/";

const isProduction = process.env.NODE_ENV === "production";

function cookieOptions() {
  return {
    signed: true,
    httpOnly: true,
    secure: isProduction,
    // Cross-site POST mora moći poslati cookie u Render demonstraciji.
    // Lokalni localhost:3000 i localhost:4000 su isti site.
    sameSite: isProduction ? "none" : "lax",
    maxAge: 60 * 60 * 1000,
    path: "/"
  };
}

function clearCookieOptions() {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? "none" : "lax",
    path: "/"
  };
}

function initCookieAuth(app, pageLoginUrl = "/") {
  loginUrl = pageLoginUrl;
  app.use(cookieParser(process.env.COOKIE_KEY));
  app.use(setUserInfo);
}

// Nema XSS demonstracije pa je httpOnly uvijek uključen.
// Vraćamo CSRF token kako bi ga EJS mogao staviti u legitimne forme.
function signInUser(res, username) {
  const csrfToken = cryptoRandomToken();

  res.cookie("user", username, cookieOptions());
  res.cookie("csrfToken", csrfToken, cookieOptions());

  return csrfToken;
}

function signOutUser(res) {
  res.clearCookie("user", clearCookieOptions());
  res.clearCookie("csrfToken", clearCookieOptions());
}

function setUserInfo(req, res, next) {
  const username = req.signedCookies?.user;
  const csrfToken = req.signedCookies?.csrfToken;

  if (typeof username === "string" && username.length > 0) {
    req.user = { username };
  }

  if (typeof csrfToken === "string" && csrfToken.length > 0) {
    req.csrfToken = csrfToken;
  }

  next();
}

function requiresAuthentication(req, res, next) {
  if (req.user) {
    return next();
  }

  const returnUrl = encodeURIComponent(req.originalUrl || req.url || "/");
  return res.redirect(302, `${loginUrl}?returnUrl=${returnUrl}`);
}

function cryptoRandomToken() {
  return randomBytes(32).toString("hex");
}

export { initCookieAuth, signInUser, signOutUser, requiresAuthentication };
