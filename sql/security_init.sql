--
-- groups and authorities
--   run either as auth_admin_user or auth_server_user
--
insert into spring.groups (group_name) values ('SYSTEM_ADMIN');
insert into spring.groups (group_name) values ('API_USER');
insert into spring.groups (group_name) values ('PRODUCT_ADMIN');

insert into spring.group_authorities (group_id, authority) select id, 'ROLE_USER' from spring.groups where group_name = 'SYSTEM_ADMIN';
insert into spring.group_authorities (group_id, authority) select id, 'ROLE_SYSTEM_ADMIN' from spring.groups where group_name = 'SYSTEM_ADMIN';

insert into spring.group_authorities (group_id, authority) select id, 'ROLE_USER' from spring.groups where group_name = 'API_USER';

insert into spring.group_authorities (group_id, authority) select id, 'ROLE_USER' from spring.groups where group_name = 'PRODUCT_ADMIN';
insert into spring.group_authorities (group_id, authority) select id, 'ROLE_ADMIN' from spring.groups where group_name = 'PRODUCT_ADMIN';


-- danalms as system admin
DO $$
DECLARE
  userid VARCHAR(20);
  groupid INTEGER ;
BEGIN

userid := 'danalms';
-- password: L@stw0rd1960
insert into spring.users
(username, password, enabled, locked, password_expiry, first_name, last_name, email_address)
values
(userid, '06caba1d08c763a84b8c82cf30c954cd3915f291b62fd3d70799b9534cd75dc0a637f1fd5c1a6d0f',
 true, false, null, 'Dan','Alms', 'dan@rosssoftwareworks.com');

select id from spring.groups into groupid where group_name = 'SYSTEM_ADMIN';

insert into spring.group_members
(username, group_id)
values
(userid, groupid);

END $$;
