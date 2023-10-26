const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const { initializeDatabase, queryDB } = require("./database");
const jwt = require("jsonwebtoken");
const expressPino = require('pino-http');
const logger = require('../.request-log.js');
const rotatingLogFileModule = require('@vrbo/pino-rotating-file');
console.log(rotatingLogFileModule);

let db;
const jwtSecret = process.env.JWT_SECRET || "supersecret";

const initializeAPI = async (app) => {
  app.use(expressPino({ logger }));

  logger.info('Initializing API and connecting to database...');
  db = initializeDatabase();
  
  app.post("/api/login", body("username").notEmpty().withMessage("Username is required."), login);
  app.get("/api/posts", getPosts);
  app.post("/api/create-post", createPost);
};

const login = async (req, res) => {
  req.log.info(`INFO Login attempt by ${req.body.username}`);

  const result = validationResult(req);
  if (!result.isEmpty()) {
    req.log.warn('Login validation errors detected');
    return res.status(400).json(result.array());
  }

  const { username, password } = req.body;

  // Use parameterized query to prevent SQL injection
  const user = await queryDB(db, `SELECT * FROM users WHERE username = ?`, [username]);
  
  if (user.length === 0) {
    req.log.warn(`ERROR Login attempt failed for username: ${username}`);
    return res.status(401).json({ error: "Invalid username or password." });
  }

  const match = await bcrypt.compare(password, user[0].password);
  if (!match) {
    req.log.warn(`ERROR Incorrect password for username: ${username}`);
    return res.status(401).json({ error: "Invalid username or password." });
  }

  req.log.info(`INFO User ${username} logged in successfully.`);
  const token = jwt.sign({ username }, jwtSecret, { expiresIn: '1h' });
  return res.json({ token });
};

const getPosts = (req, res) => {
  req.log.info('Fetching all posts');
  res.send(posts);
};

const createPost = async (req, res) => {
  req.log.info(`Creating post with title: ${req.body.title}`);
  
  const result = validationResult(req);
  if (!result.isEmpty()) {
    req.log.warn('Post creation validation errors detected');
    return res.status(400).json(result.array());
  }

  const { title, content } = req.body;

  // Use parameterized query to prevent SQL injection
  await queryDB(db, 'INSERT INTO posts (title, content) VALUES (?, ?)', [title, content]);
  
  req.log.info(`INFO Post with title: ${req.body.title} created successfully.`);
  res.status(201).json({ message: "Post created!" });
};

module.exports = { initializeAPI };
