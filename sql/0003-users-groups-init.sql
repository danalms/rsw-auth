--
-- !!! run as auth_admin_user or auth_server_user with authdb as default database !!!
-- This SQL can be run either via copy/paste into a client GUI or via command line
--  command line:  psql -U auth_admin_user -d authdb -a -f 0003-users-groups-init.sql
--
-- Example groups and authorities ...
--   group usage is optional
--   can just use plain authorities
--   ACL configurations would probably use simple authorities
--

--
-- create groups
--
insert into groups (group_name) values ('SYSTEM_ADMIN');
insert into groups (group_name) values ('API_USER');
insert into groups (group_name) values ('API_ADMIN');

insert into group_authorities (group_id, authority) select id, 'ROLE_USER' from groups where group_name = 'SYSTEM_ADMIN';
insert into group_authorities (group_id, authority) select id, 'ROLE_SYSTEM_ADMIN' from groups where group_name = 'SYSTEM_ADMIN';

insert into group_authorities (group_id, authority) select id, 'ROLE_USER' from groups where group_name = 'API_USER';

insert into group_authorities (group_id, authority) select id, 'ROLE_USER' from groups where group_name = 'API_ADMIN';
insert into group_authorities (group_id, authority) select id, 'ROLE_ADMIN' from groups where group_name = 'API_ADMIN';


--
-- create users
--
DO $$
DECLARE
  userid VARCHAR(20);
  groupid INTEGER ;
BEGIN

  --
  --  Admin User
  --
  userid := 'admin';
  -- password: P@ssw0rd
  insert into users
  (username, password, enabled, locked, password_expiry, first_name, last_name, email_address)
  values
  (userid, '$2a$10$BGAQtsGbrlDSCepouH84J.wvllgEKZEB2e9OBNJCXpKa3IQoTui.e',
   true, false, null, 'System','Admin', 'admin@example.com');

  select id from groups into groupid where group_name = 'SYSTEM_ADMIN';

  insert into group_members
  (username, group_id)
  values
  (userid, groupid);

  --
  --  Standard API User
  --
  userid := 'apiuser';
  -- password: P@ssw0rd
  insert into users
  (username, password, enabled, locked, password_expiry, first_name, last_name, email_address)
  values
    (userid, '$2a$10$BGAQtsGbrlDSCepouH84J.wvllgEKZEB2e9OBNJCXpKa3IQoTui.e',
     true, false, null, 'Api','User', 'apiuser@example.com');

  select id from groups into groupid where group_name = 'API_USER';

  insert into group_members
  (username, group_id)
  values
    (userid, groupid);

  --
  --  API Admin
  --
  userid := 'apiadmin';
  -- password: P@ssw0rd
  insert into users
  (username, password, enabled, locked, password_expiry, first_name, last_name, email_address)
  values
    (userid, '$2a$10$BGAQtsGbrlDSCepouH84J.wvllgEKZEB2e9OBNJCXpKa3IQoTui.e',
     true, false, null, 'Api','Admin', 'apiadmin@example.com');

  select id from groups into groupid where group_name = 'API_ADMIN';

  insert into group_members
  (username, group_id)
  values
    (userid, groupid);

END $$;
