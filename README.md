# auth-server-demo

Example of a minimally configured OAuth2 Authorization Server as implemented by Spring Security with Spring Boot

There are two alternate configurations, enabled by the **gateway.demo.tokenType** property: *jwt* or *oauth2*, which
demonstrates either returning JWT tokens ("by value") or OAuth2 tokens ("by reference")

A working client of this server is found in the *gateway-demo* repo (a Zuul gateway) and the *product-api-demo* repo,
(a micro service proxied by the gateway/Zuul server).
See [gateway-demo](https://github.com/danalms/gateway-demo/blob/master/README.md) for gateway details

This AuthServer example has a built-in login form invoked on /oauth/authorize prior to granting an OAuth token

For demonstration purposes, the login form authenticates against the Spring Security built-in user account 'user', with a
password of 'password' (property override of the randomly generated GUID password)


*Note about Redis...* 

Redis would be useful when/if you are running multiple load balanced instances of the auth server, and 
if you are not using JWT tokens which are stateless, but using plain OAuth2 tokens which are not.

Redis would be used in two ways:
1. HttpSession backed by Redis would ensure browser-auth server interactions don't get confused
(this may be required even if using JWTs in a load balanced situation)
2. RedisTokenStore would need to be configured as persistent token store to ensure 
that tokens are recognized by all auth server instances for resource details lookups 

