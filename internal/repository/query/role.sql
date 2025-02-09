-- name: GetRoleByName :one
SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolconnlimit, rolpassword, rolvaliduntil, rolbypassrls, rolconfig
FROM pg_catalog.pg_roles 
WHERE rolname = '$1';
