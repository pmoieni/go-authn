CREATE TABLE users (
  id    BIGINT  NOT NULL AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255)    NOT NULL,
  first_name VARCHAR(255),
  last_name VARCHAR(255),
  picture VARCHAR(255),
  UNIQUE (email)
);
