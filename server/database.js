const sqlite3 = require("sqlite3").verbose();
const dotenv = require("dotenv");
dotenv.config(); // Lädt die Umgebungsvariablen aus der .env-Datei
const aesSecret = process.env.AES_SECRET; // Holt das AES-Secret aus der Umgebungsvariable

const initializeDatabase = () => {
  const db = new sqlite3.Database("./my-database.db");
  return db;
};

const insertDB = (db, query) => {
  return new Promise((resolve, reject) => {
    db.run(query, [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

const queryDB = (db, query) => {
  return new Promise((resolve, reject) => {
    db.all(query, [], (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

module.exports = { initializeDatabase, queryDB, insertDB };
