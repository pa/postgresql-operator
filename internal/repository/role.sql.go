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
SELECT rolname, rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, rolpassword, rolvaliduntil, rolbypassrls, rolconfig, oid
FROM pg_catalog.pg_roles 
WHERE rolname = $1
`

type GetRoleByNameRow struct {
	Rolname        pgtype.Text        `json:"rolname"`
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
	Oid            pgtype.Uint32      `json:"oid"`
}

func (q *Queries) GetRoleByName(ctx context.Context, rolname pgtype.Text) (GetRoleByNameRow, error) {
	row := q.db.QueryRow(ctx, getRoleByName, rolname)
	var i GetRoleByNameRow
	err := row.Scan(
		&i.Rolname,
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
		&i.Oid,
	)
	return i, err
}

const getRolePasswordHash = `-- name: GetRolePasswordHash :one
SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = $1
`

func (q *Queries) GetRolePasswordHash(ctx context.Context, rolname string) (pgtype.Text, error) {
	row := q.db.QueryRow(ctx, getRolePasswordHash, rolname)
	var rolpassword pgtype.Text
	err := row.Scan(&rolpassword)
	return rolpassword, err
}

const isRoleInSync = `-- name: IsRoleInSync :one
SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_roles
    WHERE rolname = $1
    AND COALESCE(rolsuper, false) = $2
    AND COALESCE(rolinherit, false) = $3
    AND COALESCE(rolcreaterole, false) = $4
    AND COALESCE(rolcreatedb, false) = $5
    AND COALESCE(rolcanlogin, false) = $6
    AND COALESCE(rolreplication, false) = $7
    AND rolconnlimit = $8
    AND COALESCE(rolbypassrls, false) = $9
    AND rolconfig = $10
) AS exists
`

type IsRoleInSyncParams struct {
	Rolname        pgtype.Text `json:"rolname"`
	Rolsuper       pgtype.Bool `json:"rolsuper"`
	Rolinherit     pgtype.Bool `json:"rolinherit"`
	Rolcreaterole  pgtype.Bool `json:"rolcreaterole"`
	Rolcreatedb    pgtype.Bool `json:"rolcreatedb"`
	Rolcanlogin    pgtype.Bool `json:"rolcanlogin"`
	Rolreplication pgtype.Bool `json:"rolreplication"`
	Rolconnlimit   pgtype.Int4 `json:"rolconnlimit"`
	Rolbypassrls   pgtype.Bool `json:"rolbypassrls"`
	Rolconfig      interface{} `json:"rolconfig"`
}

func (q *Queries) IsRoleInSync(ctx context.Context, arg IsRoleInSyncParams) (bool, error) {
	row := q.db.QueryRow(ctx, isRoleInSync,
		arg.Rolname,
		arg.Rolsuper,
		arg.Rolinherit,
		arg.Rolcreaterole,
		arg.Rolcreatedb,
		arg.Rolcanlogin,
		arg.Rolreplication,
		arg.Rolconnlimit,
		arg.Rolbypassrls,
		arg.Rolconfig,
	)
	var exists bool
	err := row.Scan(&exists)
	return exists, err
}
