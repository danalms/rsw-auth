# rsw-auth

Example of a PostgreSQL-backed OAuth2 Authorization Server as implemented by Spring Security with Spring Boot

There are two alternate configurations, enabled by the **auth.tokenType** property: *jwt* or *oauth2*, which
demonstrates either returning JWT tokens ("by value") or OAuth2 tokens ("by reference")

A working client of this server is found in the *rsw-gateway* repo, a Zuul gateway, and the *rsw-product* repo,
a micro service proxied by the gateway/Zuul server.
See [rsw-gateway](https://github.com/danalms/rsw-gateway/blob/master/README.md) for gateway details

This AuthServer example has a built-in login form invoked on /oauth/authorize prior to granting an OAuth token

The login form authenticates against any of the creds setup in the *sql/0003-users-groups-init.sql* script
This is functional only if a local db is created with the DDL provided in the other scripts in the *sql* folder.


*Note about Redis...* 

Redis would be useful when/if you are running multiple load balanced instances of the auth server, and 
if you are not using JWT tokens which are stateless, but using plain OAuth2 tokens which are not.

Redis would be used in two ways:
1. HttpSession backed by Redis would ensure browser-auth server interactions don't get confused
(this may be required even if using JWTs in a load balanced situation)
2. RedisTokenStore would need to be configured as persistent token store to ensure 
that tokens are recognized by all auth server instances for resource details lookups 

