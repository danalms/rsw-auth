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
-- include spring first as current schema for this connection
--
SET search_path = spring, pg_catalog;

--
-- include spring first as current schema for all future connections
--
ALTER DATABASE authdb
SET search_path = spring,pg_catalog;

--
-- users
--
CREATE TABLE users (
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
CREATE UNIQUE INDEX ix_uq_users ON users (lower(username));

--
-- authorities
--
CREATE TABLE authorities (
  username VARCHAR(50) NOT NULL,
  authority VARCHAR(50) NOT NULL
);
ALTER TABLE authorities
  ADD CONSTRAINT fk_authorities_users FOREIGN KEY(username) REFERENCES users(username);
CREATE INDEX ix_authorities_users ON authorities (lower(username));
CREATE UNIQUE INDEX ix_uq_authorities on authorities (lower(username),lower(authority));

--
-- groups
--
CREATE TABLE groups (
  id SERIAL,
  group_name VARCHAR(50) NOT NULL,
  CONSTRAINT pk_groups PRIMARY KEY (id)
);
CREATE UNIQUE INDEX ix_uq_groups ON groups (group_name);

--
-- group_authorities
--
CREATE TABLE group_authorities (
  group_id INTEGER NOT NULL,
  authority varchar(50) NOT NULL
);
ALTER TABLE group_authorities
  ADD CONSTRAINT fk_group_authorities_groups FOREIGN KEY(group_id) REFERENCES groups(id);
CREATE INDEX ix_group_authorities_groups ON group_authorities (group_id);

--
-- group_members
--
CREATE TABLE group_members (
  id SERIAL,
  username VARCHAR(50) NOT NULL,
  group_id INTEGER NOT NULL,
  PRIMARY KEY (id)
);
ALTER TABLE group_members
  ADD CONSTRAINT fk_group_members_users FOREIGN KEY (username) REFERENCES users (username);
CREATE INDEX ix_group_members_users ON group_members (lower(username));
ALTER TABLE group_members
  ADD CONSTRAINT fk_group_members_groups FOREIGN KEY (group_id) REFERENCES groups (id);
CREATE INDEX ix_group_members_groups ON group_members (group_id);
CREATE UNIQUE INDEX ix_uq_group_members on group_members (group_id, lower(username));


CREATE TABLE persistent_logins (
  series VARCHAR(64) NOT NULL,
  username VARCHAR(64) NOT NULL,
  token VARCHAR(64) NOT NULL,
  last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (series)
);
ALTER TABLE persistent_logins
  ADD CONSTRAINT fk_persistent_logins_users FOREIGN KEY (username) REFERENCES users (username);
CREATE INDEX ix_persistent_logins_users ON persistent_logins (lower(username));


CREATE TABLE password_history (
  id SERIAL,
  username VARCHAR(50) NOT NULL,
  password VARCHAR(256) NOT NULL,
  changed_date TIMESTAMP NOT NULL,
  PRIMARY KEY (id)
);
ALTER TABLE password_history
  ADD CONSTRAINT fk_password_history_users FOREIGN KEY (username) REFERENCES users (username);
CREATE INDEX ix_password_history_users ON password_history (lower(username) ASC );

--
--  Spring ACL model
--

--
-- acl_sid
--
CREATE TABLE acl_sid(
  id bigserial not null primary key,
  principal boolean not null,
  sid varchar(100) not null,
  constraint unique_uk_1 unique(sid,principal)
);

--
-- acl_class
--
CREATE TABLE acl_class(
  id bigserial not null primary key,
  class varchar(100) not null,
  constraint unique_uk_2 unique(class)
);

--
-- acl_object_identity
--
CREATE TABLE acl_object_identity(
  id bigserial primary key,
  object_id_class bigint not null,
  object_id_identity bigint not null,
  parent_object bigint,
  owner_sid bigint,
  entries_inheriting boolean not null,
  constraint unique_uk_3 unique(object_id_class,object_id_identity),
  constraint foreign_fk_1 foreign key(parent_object)references acl_object_identity(id),
  constraint foreign_fk_2 foreign key(object_id_class)references acl_class(id),
  constraint foreign_fk_3 foreign key(owner_sid)references acl_sid(id)
);

--
-- acl_entry
--
CREATE TABLE acl_entry(
  id bigserial primary key,
  acl_object_identity bigint not null,
  ace_order int not null,
  sid bigint not null,
  mask integer not null,
  granting boolean not null,
  audit_success boolean not null,
  audit_failure boolean not null,
  constraint unique_uk_4 unique(acl_object_identity,ace_order),
  constraint foreign_fk_4 foreign key(acl_object_identity) references acl_object_identity(id),
  constraint foreign_fk_5 foreign key(sid) references acl_sid(id)
);

