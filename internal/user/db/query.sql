-- name: GetUser :one
SELECT * FROM users
WHERE id = ? LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY email;

-- name: CreateUser :execresult
INSERT INTO users (
  email, first_name, last_name, picture
) VALUES (
  ?, ?, ?, ?
);

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = ?;
