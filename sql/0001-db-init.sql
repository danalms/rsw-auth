--
-- authdb, roles and users
--  run this script as default postgres user, or a user with superuser privs
--  (most installations create a 'postgres' user with a 'postgres' db and user is created with no password)
--
DROP DATABASE IF EXISTS authdb;
DROP SCHEMA IF EXISTS spring CASCADE;
DROP ROLE IF EXISTS auth_admin_role;
DROP ROLE IF EXISTS auth_admin_user;
DROP ROLE IF EXISTS auth_app_role;
DROP ROLE IF EXISTS auth_server_user;

CREATE ROLE auth_admin_role
SUPERUSER CREATEDB CREATEROLE REPLICATION
VALID UNTIL 'infinity';

CREATE ROLE auth_admin_user LOGIN ENCRYPTED PASSWORD 'ills66?nods'
NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT
VALID UNTIL 'infinity';

GRANT auth_admin_role TO auth_admin_user;

CREATE ROLE auth_app_role
  NOSUPERUSER NOCREATEDB NOCREATEROLE REPLICATION
VALID UNTIL 'infinity';

CREATE ROLE auth_server_user LOGIN ENCRYPTED PASSWORD 's0ho-shenanigan'
NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT
VALID UNTIL 'infinity';

GRANT auth_app_role TO auth_server_user;

CREATE DATABASE authdb
WITH ENCODING='UTF8'
OWNER=auth_admin_role
CONNECTION LIMIT=-1;

GRANT ALL ON DATABASE authdb TO GROUP auth_admin_role WITH GRANT OPTION;
GRANT CONNECT ON DATABASE authdb TO GROUP auth_app_role WITH GRANT OPTION;

