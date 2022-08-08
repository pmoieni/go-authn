CREATE TABLE users (
  id    BIGINT  NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255)    NOT NULL,
  username  VARCHAR(255)    NOT NULL,
  UNIQUE (email,username)
);
