// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: role.sql

package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
)

const getRoleByName = `-- name: GetRoleByName :one
SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, rolpassword, rolvaliduntil, rolbypassrls, rolconfig
FROM pg_catalog.pg_roles 
WHERE rolname = '$1'
`

type GetRoleByNameRow struct {
	Rolsuper       pgtype.Bool        `json:"rolsuper"`
	Rolinherit     pgtype.Bool        `json:"rolinherit"`
	Rolcreaterole  pgtype.Bool        `json:"rolcreaterole"`
	Rolcreatedb    pgtype.Bool        `json:"rolcreatedb"`
	Rolcanlogin    pgtype.Bool        `json:"rolcanlogin"`
	Rolreplication pgtype.Bool        `json:"rolreplication"`
	Rolconnlimit   pgtype.Int4        `json:"rolconnlimit"`
	Rolpassword    pgtype.Text        `json:"rolpassword"`
	Rolvaliduntil  pgtype.Timestamptz `json:"rolvaliduntil"`
	Rolbypassrls   pgtype.Bool        `json:"rolbypassrls"`
	Rolconfig      interface{}        `json:"rolconfig"`
}

func (q *Queries) GetRoleByName(ctx context.Context) (GetRoleByNameRow, error) {
	row := q.db.QueryRow(ctx, getRoleByName)
	var i GetRoleByNameRow
	err := row.Scan(
		&i.Rolsuper,
		&i.Rolinherit,
		&i.Rolcreaterole,
		&i.Rolcreatedb,
		&i.Rolcanlogin,
		&i.Rolreplication,
		&i.Rolconnlimit,
		&i.Rolpassword,
		&i.Rolvaliduntil,
		&i.Rolbypassrls,
		&i.Rolconfig,
	)
	return i, err
}
