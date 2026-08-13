-- ${APP_USER} (personal superuser)
SELECT 'CREATE USER ' || quote_ident('${APP_USER}') || ' WITH PASSWORD ' || quote_literal('${APP_PASSWORD}') || ' SUPERUSER CREATEDB CREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}')
\gexec

SELECT 'ALTER USER ' || quote_ident('${APP_USER}') || ' WITH PASSWORD ' || quote_literal('${APP_PASSWORD}')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = '${APP_USER}')
\gexec

-- svc_gitopsdeploy
SELECT 'CREATE USER svc_gitopsdeploy WITH PASSWORD ' || quote_literal('${SVC_GITOPSDEPLOY_PASSWORD}') || ' CREATEDB CREATEROLE'
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_gitopsdeploy')
\gexec

SELECT 'ALTER USER svc_gitopsdeploy WITH PASSWORD ' || quote_literal('${SVC_GITOPSDEPLOY_PASSWORD}')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_gitopsdeploy')
\gexec

-- svc_grampsweb
SELECT 'CREATE USER svc_grampsweb WITH PASSWORD ' || quote_literal('${SVC_GRAMPSWEB_PASSWORD}')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_grampsweb')
\gexec

SELECT 'ALTER USER svc_grampsweb WITH PASSWORD ' || quote_literal('${SVC_GRAMPSWEB_PASSWORD}')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_grampsweb')
\gexec

-- svc_nextcloud
SELECT 'CREATE USER svc_nextcloud WITH PASSWORD ' || quote_literal('${SVC_NEXTCLOUD_PASSWORD}')
WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_nextcloud')
\gexec

SELECT 'ALTER USER svc_nextcloud WITH PASSWORD ' || quote_literal('${SVC_NEXTCLOUD_PASSWORD}')
WHERE EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_nextcloud')
\gexec

-- databases (unchanged — already working)
SELECT 'CREATE DATABASE grampsweb_users OWNER svc_grampsweb'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'grampsweb_users')
\gexec

SELECT 'CREATE DATABASE grampsweb_search OWNER svc_grampsweb'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'grampsweb_search')
\gexec

-- Gramps' plain PostgreSQL addon (single-tree backend, GRAMPSWEB_NEW_DB_BACKEND:
-- postgresql) requires the database name to exactly match the tree name
-- (GRAMPSWEB_TREE) - it never issues CREATE DATABASE itself, only connects.
SELECT 'CREATE DATABASE "James-Fagg_Family" OWNER svc_grampsweb'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'James-Fagg_Family')
\gexec

SELECT 'CREATE DATABASE nextcloud OWNER svc_nextcloud'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'nextcloud')
\gexec