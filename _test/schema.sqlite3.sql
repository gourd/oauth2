--
-- example schema
-- --------------
-- schema file for sqlite3 database
-- to be used in this example
--

--
-- example data
--
DROP TABLE IF EXISTS posts;
CREATE TABLE posts (
  `id`    INTEGER PRIMARY KEY,
  `uid`   INTEGER,
  `title` TEXT,
  `body`  TEXT,
  `size`  INTEGER,
  `date`  INTEGER
);

DROP TABLE IF EXISTS comments;
CREATE TABLE comments (
  `id`      INTEGER PRIMARY KEY,
  `post_id` INTEGER,
  `title`   TEXT,
  `body`    TEXT,
  `size`    INTEGER,
  `date`    INTEGER
);


--
-- example user table
--

DROP TABLE IF EXISTS user;
CREATE TABLE user (
  `id`       INTEGER PRIMARY KEY,
  `username` TEXT,
  `email`    TEXT,
  `password` TEXT,
  `name`     TEXT,
  `created`  INTEGER,
  `updated`  INTEGER
);


--
-- OAuth2 related tables
--
DROP TABLE IF EXISTS oauth2_client;
CREATE TABLE oauth2_client (
  `id`           TEXT PRIMARY KEY,
  `secret`       TEXT,
  `redirect_uri` TEXT,
  `user_id`      TEXT
);

DROP TABLE IF EXISTS oauth2_auth;
CREATE TABLE oauth2_auth (
  `id`           INTEGER PRIMARY KEY,
  `client_id`    TEXT,
  `code`         TEXT,
  `expires_in`   INTEGER,
  `scope`        TEXT,
  `redirect_uri` TEXT,
  `state`        TEXT,
  `created_at`   INTEGER,
  `user_id`      INTEGER
);

DROP TABLE IF EXISTS oauth2_access;
CREATE TABLE oauth2_access (
  `id`                INTEGER PRIMARY KEY,
  `client_id`         TEXT,
  `auth_code`         TEXT,
  `access_token`      TEXT,
  `prev_access_token` TEXT,
  `refresh_token`     TEXT,
  `expires_in`        INTEGER,
  `scope`             TEXT,
  `redirect_uri`      TEXT,
  `state`             TEXT,
  `created_at`        INTEGER,
  `user_id`           INTEGER
);
