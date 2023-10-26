const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const { initializeDatabase, queryDB } = require("./database");
const jwt = require("jsonwebtoken");
const pino = require('pino');
const expressPino = require('pino-http');
const rotatingLogStream = require('@vrbo/pino-rotating-file');
const logger = require('../.request-log.js');



let db;
const jwtSecret = process.env.JWT_SECRET || "supersecret";

/*
const logger = pino(
    {
      level: 'info',
    },
    rotatingLogStream({
      path: 'logs', // Pfad, in dem die Logdateien gespeichert werden
      size: '1MB',  // Maximale Größe jeder Datei
      count: 5      // Anzahl der Logdateien, die behalten werden
    })
  );
*/

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


/*
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcrypt");
const { initializeDatabase, queryDB } = require("./database");
const jwt = require("jsonwebtoken");

let db;

const jwtSecret = process.env.JWT_SECRET || "supersecret";

const posts = [
  {
    id: 1,
    title: "Introduction to JavaScript",
    content:
      "JavaScript is a dynamic language primarily used for web development...",
  },
  {
    id: 2,
    title: "Functional Programming",
    content:
      "Functional programming is a paradigm where functions take center stage...",
  },
  {
    id: 3,
    title: "Asynchronous Programming in JS",
    content:
      "Asynchronous programming allows operations to run in parallel without blocking the main thread...",
  },
];

const initializeAPI = async (app) => {
  db = initializeDatabase();
  app.post(
    "/api/login",
    body("username")
      .notEmpty()
      .withMessage("Username is required.")
      .isEmail()
      .withMessage("Invalid email format."),
    body("password")
      .isLength({ min: 10, max: 64 })
      .withMessage("Password must be between 10 to 64 characters.")
      .escape(),
    login
  );
  app.get("/api/posts", getPosts);
};

const login = async (req, res) => {
  // Validate request
  const result = validationResult(req);
  if (!result.isEmpty()) {
    const formattedErrors = [];
    result.array().forEach((error) => {
      console.log(error);
      formattedErrors.push({ [error.path]: error.msg });
    });
    return res.status(400).json(formattedErrors);
  }

  // Check if user exists
  const { username, password } = req.body;
  const getUserQuery = `
    SELECT * FROM users WHERE username = '${username}';
  `;
  const user = await queryDB(db, getUserQuery);
  if (user.length === 0) {
    return res
      .status(401)
      .json({ username: "Username does not exist. Or Passwort is incorrect." });
  }
  // Check if password is correct
  const hash = user[0].password;
  const match = await bcrypt.compare(password, hash);
  if (!match) {
    return res
      .status(401)
      .json({ username: "Username does not exist. Or Passwort is incorrect." });
  }
  // Create JWT
  const token = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 60 * 60,
      data: { username, roles: [user[0].role] },
    },
    jwtSecret
  );

  return res.send(token);
};

const getPosts = (req, res) => {
  const authorization = req.headers.authorization;
  if (!authorization) {
    return res.status(401).json({ error: "No authorization header." });
  }
  const [prefix, token] = authorization.split(" ");
  if (prefix !== "Bearer") {
    return res.status(401).json({ error: "Invalid authorization prefix." });
  }
  const tokenValidation = jwt.verify(token, jwtSecret);
  if (!tokenValidation?.data) {
    return res.status(401).json({ error: "Invalid token." });
  }
  if (!tokenValidation.data.roles?.includes("viewer")) {
    return res.status(403).json({ error: "You are not a viewer." });
  }
  return res.send(posts);
};

module.exports = { initializeAPI };
*/