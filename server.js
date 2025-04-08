const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
require('dotenv').config()
const db = require('./mysql')

const app = express();

// Configure session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure:  process.env.NODE_ENV === 'production' }, // Only transmit cookies over HTTPS
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Configure Passport to use Google OAuth 2.0
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const [rows] = await db.query(
          'SELECT * FROM users WHERE google_id = ?',
          [profile.id]
        );

        let user;
        if (rows.length > 0) {
          user = rows[0];
        } else {
          const [result] = await db.query(
            'INSERT INTO users (google_id, display_name, email) VALUES (?, ?, ?)',
            [
              profile.id,
              profile.displayName,
              profile.emails[0].value
            ]
          );

          user = {
            id: result.insertId,
            google_id: profile.id,
            display_name: profile.displayName,
            email: profile.emails[0].value
          };
        }

        done(null, user);
      } catch (err) {
        console.error('Error saving user to the database:', err);
        done(err, null);
      }
    }
  )
);

// Serialize user information into the session
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async(id, done) => {
  try {
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [id]);
    if (rows.length > 0) {
      done(null, rows[0]); // Full user object goes to req.user
    } else {
      done(null, false); // User not found
    }
  } catch (err) {
    done(err);
  }
});

// Define routes
app.get('/', (req, res) => {
  res.send('<a href="/auth/google">Login with Google</a>');
});

// Route to initiate Google OAuth
app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

// Callback route for Google to redirect to after login
app.get(
  '/oAuth/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => {
    // console.log(req._passport);
    res.send(`<h1>Login successful</h1><p>Welcome, ${req.user.display_name}</p><h3><a href="/logout">logout</a><h3>`);
  }
);

// Route to log out
app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect('/');
  });
});

// Start the server
app.listen(3000, () => {
  console.log('Server is running on http://localhost:3000');
});
