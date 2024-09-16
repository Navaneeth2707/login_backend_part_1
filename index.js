import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import bcrypt from 'bcrypt';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import session from 'express-session';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';

dotenv.config();

const app = express();
const port = process.env.PORT || 5000;
const saltrounds = 10;

app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true,
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

app.use(helmet());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 555, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts, please try after 15 min.',
});

const registrationLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 55, // limit each IP to 5 requests per windowMs
  message: 'Too many registration attempts, please try after 15 min.',
});

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());

const pool = new pg.Pool({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [username]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) return done(err);
        if (valid) return done(null, user);
        else return done(null, false, { message: 'Incorrect password.' });
      });
    } else {
      return done(null, false, { message: 'User not found.' });
    }
  } catch (err) {
    console.error('Error during authentication:', err);
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    if (result.rows.length > 0) {
      done(null, result.rows[0]);
    } else {
      done(new Error('User not found'));
    }
  } catch (err) {
    done(err);
  }
});

app.post('/api/login', loginLimiter, passport.authenticate('local', {
  successRedirect: '/api/secrets',
  failureRedirect: '/api/login',
}));

app.post('/api/register', registrationLimiter, async (req, res) => {
  const { username: email, password } = req.body;
  try {
    const checkResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (checkResult.rows.length > 0) {
      res.status(400).json({ message: 'User already exists' });
    } else {
      bcrypt.hash(password, saltrounds, async (err, hash) => {
        if (err) {
          console.error('Error hashing password:', err);
          res.status(500).json({ message: 'Server error' });
        } else {
          const result = await pool.query(
            'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error('Login after registration failed:', err);
              res.status(500).json({ message: 'Server error' });
            } else {
              res.status(200).json({ message: 'Registration successful' });
            }
          });
        }
      });
    }
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/secrets', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ secret: 'Here is your secret data' });
  } else {
    res.status(401).json({ message: 'Unauthorized' });
  }
});

app.get('/api/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.status(200).json({ message: 'Logout successful' });
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});