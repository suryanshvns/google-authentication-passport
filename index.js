const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const crypto = require('crypto');
const env = require('dotenv').config();

const app = express();
const port = 3000;

// Generate a random secret key
const secret = crypto.randomBytes(32).toString('hex');

// Configure session middleware with the generated secret
app.use(session({
    secret: secret,
    resave: false,
    saveUninitialized: false
}));

// Initialize Passport and restore authentication state, if any, from the session
app.use(passport.initialize());
app.use(passport.session());

// Configure Google authentication strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // This function is called when a user successfully authenticates
    // You can perform any user validation or database operations here
    return cb(null, profile);
  }
));

// Serialize user object to store in session
passport.serializeUser(function(user, done) {
    done(null, user);
});

// Deserialize user object from session
passport.deserializeUser(function(user, done) {
    done(null, user);
});

// Route for initiating Google authentication
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback route after Google authentication
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to user information page
    res.redirect('/user');
  });

// Route to check if user is authenticated and display user information
app.get('/user', (req, res) => {
    if(req.isAuthenticated()) {
        const user = req.user;
        res.send(`
            <h1>Welcome, ${user.displayName}</h1>
            <p>Email: ${user.emails[0].value}</p>
            <a href="/logout">Logout</a>
        `);
    } else {
        res.redirect('/auth/google');
    }
});

// Route to logout
app.get('/logout', (req, res) => {
    req.logout();
    res.redirect('/');
});

// Route to home page
app.get('/', (req, res) => {
    res.send('Home Page');
});

// Start server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
