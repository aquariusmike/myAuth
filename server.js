import express from "express";
import session from "express-session";
import passport from "passport";
import dotenv from "dotenv";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import flash from "connect-flash";
import MongoStore from "connect-mongo";
import path from "path";
import https from "https";
import fs from "fs";

dotenv.config();

const app = express();

// -----------------------
// HTTPS CONFIGURATION (Optional for Production)
// -----------------------
// If you have SSL certs, uncomment and use HTTPS
/*
const sslOptions = {
  key: fs.readFileSync(path.resolve(__dirname, "certs/key.pem")),
  cert: fs.readFileSync(path.resolve(__dirname, "certs/cert.pem"))
};
*/

// -----------------------
// 1. MIDDLEWARE
// -----------------------

// Serve static files from 'public'
app.use(express.static(path.join(process.cwd(), "public")));

// Session Middleware (MongoStore for Production)
app.use(
  session({
    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      ttl: 14 * 24 * 60 * 60, // 14 days
      collectionName: "sessions",
      touchAfter: 24 * 3600, // Lazy session update
      autoRemove: "native", // Let MongoDB handle expired sessions
      mongoOptions: {
        serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
        socketTimeoutMS: 45000,
      }
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    rolling: true, // Reset expiration on activity
    cookie: {
      secure: process.env.NODE_ENV === "production", // Only HTTPS in production
      httpOnly: true, // Prevent client-side JS access
      maxAge: 14 * 24 * 60 * 60 * 1000, // 14 days
    },
  })
);

// Passport initialization
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

// -----------------------
// 2. GOOGLE OAUTH STRATEGY
// -----------------------
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.BASE_URL}/auth/google/callback`,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        let role = "general";
        let isAuthorized = false;

        // Condition 1: Official Student Email
        if (email.endsWith("@stu.pathfinder-mm.org")) {
          role = "student";
          isAuthorized = true;
        }

        // Condition 2: Personal Gmail Exception
        if (email === "avagarimike11@gmail.com") {
          role = "student";
          isAuthorized = true;
        }

        if (!isAuthorized) {
          return done(null, false, {
            message: "You are not a verified student of Pathfinder Institute Myanmar.",
          });
        }

        return done(null, { email, name: profile.displayName, role });
      } catch (err) {
        return done(err, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// -----------------------
// 3. AUTH ROUTES
// -----------------------

// Start Google OAuth login
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

// Google OAuth callback
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth/failure",
    failureFlash: true,
  }),
  (req, res) => {
    res.redirect("/dashboard");
  }
);

// Login failure route
app.get("/auth/failure", (req, res) => {
  const messages = req.flash("error");
  const errorMessage = messages.length ? messages[0] : "Login failed.";
  const encodedMessage = encodeURIComponent(errorMessage);
  res.redirect(`/index.html?authError=${encodedMessage}`);
});

// -----------------------
// 4. PROTECTED ROUTES
// -----------------------
function ensureLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/index.html");
}

// Dashboard
app.get("/dashboard", ensureLoggedIn, (req, res) => {
  const { name, email, role } = req.user;
  res.send(`
    <html>
      <head>
        <title>Dashboard</title>
        <style>
          body { font-family: Arial; padding: 20px; }
          .card { padding: 20px; border: 1px solid #ddd; border-radius: 10px; margin-top: 20px; }
          .stu { background: #e3f2fd; }
          .gen { background: #fff3e0; }
        </style>
      </head>
      <body>
        <h2>Welcome ${name}</h2>
        <p>Email: ${email}</p>
        <p>Role: <b>${role}</b></p>
        ${
          role === "student"
            ? `<div class="card stu"><h3>Student Docs Section</h3></div>`
            : `<div class="card gen"><h3>Enrollment Section</h3></div>`
        }
        <br>
        <a href="/logout">Logout</a>
      </body>
    </html>
  `);
});

// Logout
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    req.session.destroy(() => res.redirect("/index.html"));
  });
});

// -----------------------
// 5. START SERVER
// -----------------------
const PORT = process.env.PORT || 3000;

// If using HTTPS
/*
https.createServer(sslOptions, app).listen(PORT, () => {
  console.log(`Server running securely on https://localhost:${PORT}`);
});
*/

// Otherwise, HTTP
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`MongoDB session store initialized`);
});