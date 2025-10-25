DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS prev_passwords;

CREATE TABLE users (
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT PRIMARY KEY,
    email_address TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
);

CREATE TABLE prev_passwords (
    username TEXT,
    password_hash TEXT
);