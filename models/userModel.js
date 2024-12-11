const mysql = require('mysql2');

// Set up the database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

// Create Users table if it doesn't exist
const createTableQuery = `
    CREATE TABLE IF NOT EXISTS Users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        profile_picture LONGTEXT,
        user_level ENUM('User', 'Admin', 'Super User') DEFAULT 'User',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`;

db.query(createTableQuery, (err) => {
    if (err) throw err;
    console.log("Users table created or exists already.");
});

module.exports = db;
