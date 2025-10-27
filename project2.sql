DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS prev_passwords;
DROP TABLE IF EXISTS follow_list;

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

CREATE TABLE follow_list (
    user TEXT NOT NULL,
    follower TEXT NOT NULL,
    PRIMARY KEY (user, follower),
    FOREIGN KEY (user) REFERENCES users(username),
    FOREIGN KEY (follower) REFERENCES users(username)
);