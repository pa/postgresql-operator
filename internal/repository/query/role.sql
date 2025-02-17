-- name: GetRoleByName :one
SELECT *
FROM pg_catalog.pg_roles 
WHERE rolname = $1;

-- name: GetRolePasswordHash :one
SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolname = $1;

-- name: IsRoleInSync :one
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
) AS exists;
