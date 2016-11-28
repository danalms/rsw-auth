--
-- spring schema and spring security tables
--   + users table enhanced to include locked and password_expiry
--   + implemented groups, group_authorities and group_members tables for group abstraction
--   + including persistent_logins (remember me), though this concept may not apply in OAuth2 environments
--   + including password_history to prevent password reuse
--  run this script as the auth_admin_user with authdb set as default database

-- PostgreSQL nuances...
--  1. Indexes and unique constraints are created automatically for primary keys, but NOT for foreign keys
--  2. Effect of "auto increment" concept is achieved by using the "serial" keyword, which causes the engine
--     to create a sequence number table with default config as starting at one and incrementing by one
--  3. To create the effect of ignoring case on a varchar unique index, use the lower() function on the unique index
--
DROP SCHEMA IF EXISTS spring CASCADE;
CREATE SCHEMA spring AUTHORIZATION auth_admin_role;
GRANT ALL ON SCHEMA spring TO GROUP auth_admin_role WITH GRANT OPTION;

GRANT USAGE ON SCHEMA spring TO auth_app_role;
GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON ALL TABLES IN SCHEMA spring TO GROUP auth_app_role WITH GRANT OPTION;
GRANT USAGE
  ON ALL SEQUENCES IN SCHEMA spring TO GROUP auth_app_role WITH GRANT OPTION;
GRANT EXECUTE
  ON ALL FUNCTIONS IN SCHEMA spring TO GROUP auth_app_role WITH GRANT OPTION;

ALTER DEFAULT PRIVILEGES IN SCHEMA spring
  GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON TABLES TO auth_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA spring
  GRANT USAGE ON SEQUENCES TO auth_app_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA spring
  GRANT EXECUTE ON FUNCTIONS TO auth_app_role;

--
-- users
--
CREATE TABLE spring.users (
  username VARCHAR(20) NOT NULL,
  password VARCHAR(256) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  locked BOOLEAN NOT NULL DEFAULT FALSE,
  password_expiry TIMESTAMP NULL,
  first_name VARCHAR(20) NOT NULL,
  last_name VARCHAR(20) NOT NULL,
  middle_initial VARCHAR(1) NULL,
  email_address VARCHAR(50) NOT NULL,
  mobile_number VARCHAR(15) NULL,

  CONSTRAINT pk_users PRIMARY KEY (username)
);
CREATE UNIQUE INDEX ix_uq_users ON spring.users (lower(username));

--
-- authorities
--
CREATE TABLE spring.authorities (
  username VARCHAR(50) NOT NULL,
  authority VARCHAR(50) NOT NULL
);
ALTER TABLE spring.authorities
  ADD CONSTRAINT fk_authorities_users FOREIGN KEY(username) REFERENCES spring.users(username);
CREATE INDEX ix_authorities_users ON spring.authorities (lower(username));
CREATE UNIQUE INDEX ix_uq_authorities on spring.authorities (lower(username),lower(authority));

--
-- groups
--
CREATE TABLE spring.groups (
  id SERIAL,
  group_name VARCHAR(50) NOT NULL,
  CONSTRAINT pk_groups PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_uq_groups ON spring.groups (group_name);

--
-- group_authorities
--
CREATE TABLE spring.group_authorities (
  group_id INTEGER NOT NULL,
  authority varchar(50) NOT NULL
);
ALTER TABLE spring.group_authorities
  ADD CONSTRAINT fk_group_authorities_groups FOREIGN KEY(group_id) REFERENCES spring.groups(id);
CREATE INDEX ix_group_authorities_groups ON spring.group_authorities (group_id);

--
-- group_members
--
CREATE TABLE spring.group_members (
  id SERIAL,
  username VARCHAR(50) NOT NULL,
  group_id INTEGER NOT NULL,
  PRIMARY KEY (id)
);
ALTER TABLE spring.group_members
  ADD CONSTRAINT fk_group_members_users FOREIGN KEY (username) REFERENCES spring.users (username);
CREATE INDEX ix_group_members_users ON spring.group_members (lower(username));
ALTER TABLE spring.group_members
  ADD CONSTRAINT fk_group_members_groups FOREIGN KEY (group_id) REFERENCES spring.groups (id);
CREATE INDEX ix_group_members_groups ON spring.group_members (group_id);
CREATE UNIQUE INDEX ix_uq_group_members on spring.group_members (group_id, lower(username));


CREATE TABLE spring.persistent_logins (
  series VARCHAR(64) NOT NULL,
  username VARCHAR(64) NOT NULL,
  token VARCHAR(64) NOT NULL,
  last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (series)
);
ALTER TABLE spring.persistent_logins
  ADD CONSTRAINT fk_persistent_logins_users FOREIGN KEY (username) REFERENCES spring.users (username);
CREATE INDEX ix_persistent_logins_users ON spring.persistent_logins (lower(username));


CREATE TABLE spring.password_history (
  id SERIAL,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(256) NOT NULL,
  changed_date TIMESTAMP NOT NULL,
  PRIMARY KEY (id)
);
ALTER TABLE spring.password_history
  ADD CONSTRAINT fk_password_history_users FOREIGN KEY (username) REFERENCES spring.users (username);
CREATE INDEX ix_password_history_users ON spring.password_history (lower(username) ASC );


