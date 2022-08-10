// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.14.0
// source: query.sql

package user

import (
	"context"
	"database/sql"
)

const createUser = `-- name: CreateUser :execresult
INSERT INTO users (
  email, username
) VALUES (
  ?, ?
)
`

type CreateUserParams struct {
	Email    string `json:"email"`
	Username string `json:"username"`
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (sql.Result, error) {
	return q.exec(ctx, q.createUserStmt, createUser, arg.Email, arg.Username)
}

const deleteUser = `-- name: DeleteUser :exec
DELETE FROM users
WHERE id = ?
`

func (q *Queries) DeleteUser(ctx context.Context, id int64) error {
	_, err := q.exec(ctx, q.deleteUserStmt, deleteUser, id)
	return err
}

const getUser = `-- name: GetUser :one
SELECT id, email, username FROM users
WHERE id = ? LIMIT 1
`

func (q *Queries) GetUser(ctx context.Context, id int64) (User, error) {
	row := q.queryRow(ctx, q.getUserStmt, getUser, id)
	var i User
	err := row.Scan(&i.ID, &i.Email, &i.Username)
	return i, err
}

const listUsers = `-- name: ListUsers :many
SELECT id, email, username FROM users
ORDER BY username
`

func (q *Queries) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := q.query(ctx, q.listUsersStmt, listUsers)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []User{}
	for rows.Next() {
		var i User
		if err := rows.Scan(&i.ID, &i.Email, &i.Username); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}
